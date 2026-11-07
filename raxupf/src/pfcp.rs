use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::SystemTime,
};

use anyhow::bail;
use log::{debug, info};
use raxupf_common::{PDR_MAP_SIZE, pdr::PdrInfo};
use rs_pfcp::message::{
    AssociationSetupRequest, HeartbeatRequest, Message, MsgType, SessionDeletionRequest,
    SessionEstablishmentRequest, SessionModificationRequest,
};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, RwLock},
};

use crate::{
    StoreRules,
    association::PfcpAssociation,
    configuration::config::Configuration,
    handlers::{
        handle_association_setup_request, handle_session_deletion_request,
        handle_session_establishment_request, handle_session_modification_request,
    },
    heartbeat::handle_hearbeat_request,
    resource_manager::ResourceManager,
    session::PfcpSession,
};

pub struct PfcpContext {
    socket: UdpSocket,
    up_addr: SocketAddr,
    node_id: String,
    recovery_ts: SystemTime,
    associations: RwLock<HashMap<String, PfcpAssociation>>, // key: remote node_id
    sessions: RwLock<HashMap<u64, PfcpSession>>,            // key: allocated UP SEID
    maps: Arc<dyn StoreRules + Sync + Send>,
    gtp_addr_v4: Ipv4Addr,
    gtp_addr_v6: Option<Ipv6Addr>,
    resource_manager: Mutex<ResourceManager>,
}

impl PfcpContext {
    pub async fn new(
        maps: Arc<dyn StoreRules + Sync + Send>,
        configuration: &Configuration,
    ) -> anyhow::Result<Arc<Self>> {
        let local_addr = format!(
            "{}:{}",
            configuration.pfcp.local_addr.clone(),
            configuration.pfcp.local_port
        )
        .parse::<SocketAddr>()?;
        debug!("binding pfcp server to {local_addr}");

        Ok(Arc::new(Self {
            socket: UdpSocket::bind(local_addr).await?,
            up_addr: local_addr,
            node_id: configuration.pfcp.node_id.clone(),
            recovery_ts: SystemTime::now(), // indicates time when UPF was started
            associations: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            maps,
            gtp_addr_v4: configuration.gtpu.ipv4_addr.parse::<Ipv4Addr>()?,
            gtp_addr_v6: None,
            resource_manager: Mutex::new(ResourceManager::new()),
        }))
    }

    pub async fn compile_session(&self, session: PfcpSession) -> anyhow::Result<()> {
        let teid = match session.teid() {
            Some(teid) => teid,
            None => bail!("session has no teid, cannot compile"),
        };

        let mut ul_pdrs: Vec<PdrInfo> = session.get_ul_pdr_infos();
        ul_pdrs.sort_by_key(|pdr| pdr.precedence());
        let mut ul_pdr_slice = [PdrInfo::default(); PDR_MAP_SIZE];
        for (idx, ul_pdr) in ul_pdrs.iter().enumerate() {
            info!("inserting ul pdr: {:?}", ul_pdr);
            ul_pdr_slice[idx] = *ul_pdr;
        }

        let mut dl_pdrs: Vec<PdrInfo> = session.get_dl_pdr_infos();
        dl_pdrs.sort_by_key(|pdr| pdr.precedence());
        let mut dl_pdr_slice = [PdrInfo::default(); PDR_MAP_SIZE];
        for (idx, dl_pdr) in dl_pdrs.iter().enumerate() {
            dl_pdr_slice[idx] = *dl_pdr;
        }

        for (far_id, far) in session.fars() {
            self.maps.insert_far(*far_id, *far)?;
        }

        for (qer_id, qer) in session.qers() {
            self.maps.insert_qer(*qer_id, *qer)?;
        }

        for (urr_id, urr) in session.urrs() {
            self.maps.insert_urr(*urr_id, *urr)?;
        }

        self.maps.insert_ul_pdrs(teid, ul_pdr_slice)?;
        match (session.ue_ipv4(), session.ue_ipv6()) {
            (None, None) => bail!("session has no ue ip address, cannot compile"),
            (None, Some(_)) => {
                todo!()
            }
            (Some(ue_ipv4), None) => {
                self.maps
                    .insert_dl_pdrs_ivp4(ue_ipv4.to_bits(), dl_pdr_slice)?;
            }
            (Some(_), Some(_)) => {
                debug!("session has both ipv4 and ipv6 ue ip addresses, cannot compile");
                todo!()
            }
        };

        Ok(())
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn local_pfcp_addr(&self) -> SocketAddr {
        self.up_addr
    }

    pub fn gtp_addr_v4(&self) -> Ipv4Addr {
        self.gtp_addr_v4
    }

    pub fn gtp_addr_v6(&self) -> Option<Ipv6Addr> {
        self.gtp_addr_v6
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn recovery_ts(&self) -> SystemTime {
        self.recovery_ts
    }

    pub async fn with_association_mut<F, R>(&self, rnode_id: &str, f: F) -> Option<R>
    where
        F: FnOnce(&mut PfcpAssociation) -> R,
    {
        let mut association = self.associations.write().await;
        association.get_mut(rnode_id).map(f)
    }

    pub async fn insert_association(
        &self,
        remote_nodeid: &str,
        association: PfcpAssociation,
    ) -> Option<PfcpAssociation> {
        self.associations
            .write()
            .await
            .insert(remote_nodeid.to_string(), association)
    }

    pub async fn get_session(&self, key: u64) -> Option<PfcpSession> {
        let sessions = self.sessions.read().await;
        sessions.get(&key).cloned()
    }

    pub async fn insert_session(&self, lseid: u64, session: PfcpSession) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(lseid, session);
    }

    pub async fn delete_session(&self, lseid: u64) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(&lseid);
    }

    pub async fn send_response(&self, bytes: &[u8], to: SocketAddr) -> anyhow::Result<()> {
        if let Ok(n) = self.socket.send_to(bytes, to).await {
            debug!("sent {} bytes to {:?}", n, to);
        };
        Ok(())
    }

    pub async fn allocate_local_teid(&self) -> anyhow::Result<rs_pfcp::Teid> {
        self.resource_manager.lock().await.allocate_local_fteid()
    }

    pub async fn allocate_local_teid_chid(&self, choose_id: u8) -> anyhow::Result<rs_pfcp::Teid> {
        self.resource_manager
            .lock()
            .await
            .allocate_local_fteid_chid(choose_id)
    }

    pub async fn allocate_ue_ipv4(&self) -> anyhow::Result<Ipv4Addr> {
        self.resource_manager.lock().await.allocate_ue_ipv4()
    }

    pub async fn allocate_ue_ipv6(&self) -> anyhow::Result<Ipv6Addr> {
        self.resource_manager.lock().await.allocate_ue_ipv6()
    }
}

pub async fn handle_messages(ctx: Arc<PfcpContext>) -> anyhow::Result<()> {
    let mut buf = [0; 4096];

    tokio::task::spawn(async move {
        while let Ok((len, cp_addr)) = ctx.socket.recv_from(&mut buf).await {
            debug!("{:?} bytes received from {:?}", len, cp_addr);
            let res_bytes = match rs_pfcp::message::parse(&buf[..len]) {
                Ok(msg) => match msg.msg_type() {
                    MsgType::AssociationSetupRequest => {
                        debug!("incoming association setup request from {:?}", cp_addr);
                        let req = AssociationSetupRequest::unmarshal(&buf[..len]).unwrap();
                        handle_association_setup_request(&ctx, &req, cp_addr)
                            .await
                            .unwrap()
                            .marshal()
                    }
                    MsgType::HeartbeatRequest => {
                        let req = HeartbeatRequest::unmarshal(&buf[..len]).unwrap();
                        handle_hearbeat_request(&ctx, &req).await.unwrap().marshal()
                    }
                    MsgType::SessionEstablishmentRequest => {
                        debug!("incoming session establishment request from {:?}", cp_addr);
                        let req = SessionEstablishmentRequest::unmarshal(&buf[..len]).unwrap();
                        handle_session_establishment_request(&ctx, &req)
                            .await
                            .unwrap()
                            .marshal()
                    }
                    MsgType::SessionModificationRequest => {
                        debug!("incoming session modification request");
                        let req = SessionModificationRequest::unmarshal(&buf[..len]).unwrap();
                        handle_session_modification_request(&ctx, &req)
                            .await
                            .unwrap()
                            .marshal()
                    }
                    MsgType::SessionDeletionRequest => {
                        let req = SessionDeletionRequest::unmarshal(&buf[..len]).unwrap();
                        handle_session_deletion_request(&ctx, &req)
                            .await
                            .unwrap()
                            .marshal()
                    }
                    _ => {
                        debug!("unsupported message type received");
                        continue;
                    }
                },
                Err(_) => todo!(),
            };

            ctx.send_response(&res_bytes, cp_addr).await.unwrap();
        }
    });

    Ok(())
}
