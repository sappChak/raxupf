use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::SystemTime,
};

use anyhow::bail;
use aya::Ebpf;
use log::debug;
use raxupf_common::{PDR_MAP_SIZE, pdr::PdrInfo};
use rs_pfcp::message::{
    AssociationSetupRequest, Message, MsgType, SessionEstablishmentRequest,
    SessionModificationRequest,
};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, RwLock},
};

use crate::{
    BpfMaps,
    association::{PfcpAssociation, handle_association_setup_request},
    configuration::config::Configuration,
    heartbeat::handle_hearbeat_request,
    resource_manager::ResourceManager,
    session::{
        PfcpSession, handle_session_establishment_request, handle_session_modification_request,
    },
};

const PFCP_PORT: u16 = 8805; // 3GPP TS 29.244 Release 17, clause 4.2.2

pub struct PfcpContext {
    socket: UdpSocket,
    up_addr: SocketAddr,
    cp_addr: SocketAddr,
    node_id: String,
    recovery_ts: SystemTime,
    associations: RwLock<HashMap<String, PfcpAssociation>>, // key: remote node_id
    sessions: RwLock<HashMap<u64, PfcpSession>>,            // key: allocated UP TEID
    maps: BpfMaps,
    gtp_addr_v4: Ipv4Addr,
    gtp_addr_v6: Option<Ipv6Addr>,
    resource_manager: Mutex<ResourceManager>,
}

impl PfcpContext {
    pub async fn new(ebpf: &mut Ebpf, configuration: &Configuration) -> anyhow::Result<Arc<Self>> {
        let local_addr = format!("{}:{}", configuration.pfcp.local_addr.clone(), PFCP_PORT)
            .parse::<SocketAddr>()?;
        let remote_addr = format!("{}:{}", configuration.pfcp.remote_addr.clone(), PFCP_PORT)
            .parse::<SocketAddr>()?;

        Ok(Arc::new(Self {
            socket: UdpSocket::bind(local_addr).await?,
            up_addr: local_addr,
            cp_addr: remote_addr,
            node_id: configuration.pfcp.node_id.clone(),
            recovery_ts: SystemTime::now(),
            associations: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            maps: BpfMaps::new(ebpf)?,
            gtp_addr_v4: configuration.gtpu.ipv4_addr.parse::<Ipv4Addr>()?,
            gtp_addr_v6: None,
            resource_manager: Mutex::new(ResourceManager::new()),
        }))
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn local_pfcp_addr(&self) -> SocketAddr {
        self.up_addr
    }

    pub fn cp_addr(&self) -> SocketAddr {
        self.cp_addr
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
        rnode_id: &str,
        association: PfcpAssociation,
    ) -> Option<PfcpAssociation> {
        self.associations
            .write()
            .await
            .insert(rnode_id.to_string(), association)
    }

    pub async fn get_session(&self, key: u64) -> Option<PfcpSession> {
        let sessions = self.sessions.read().await;
        sessions.get(&key).cloned()
    }

    pub async fn insert_session(&self, lseid: u64, session: PfcpSession) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(lseid, session);
    }

    pub async fn compile_session(&self, session: PfcpSession) -> anyhow::Result<()> {
        let teid = match session.teid() {
            Some(teid) => teid,
            None => bail!("session has no TEID, cannot compile"),
        };

        let mut ul_pdrs: Vec<PdrInfo> = session.ul_pdrs.values().cloned().collect();
        ul_pdrs.sort_by_key(|pdr| pdr.precedence());
        let mut ul_pdr_slice = [PdrInfo::default(); PDR_MAP_SIZE];
        for (idx, ul_pdr) in ul_pdrs.iter().enumerate() {
            ul_pdr_slice[idx] = *ul_pdr;
        }

        let mut dl_pdrs: Vec<PdrInfo> = session.dl_pdrs.values().cloned().collect();
        dl_pdrs.sort_by_key(|pdr| pdr.precedence());
        let mut dl_pdr_slice = [PdrInfo::default(); PDR_MAP_SIZE];
        for (idx, dl_pdr) in dl_pdrs.iter().enumerate() {
            dl_pdr_slice[idx] = *dl_pdr;
        }

        for (far_id, far) in &session.fars {
            self.maps.insert_far(*far_id, *far).await?;
        }

        for (qer_id, qer) in &session.qers {
            self.maps.insert_qer(*qer_id, *qer).await?;
        }

        for (urr_id, urr) in &session.urrs {
            self.maps.insert_urr(*urr_id, *urr).await?;
        }

        self.maps.insert_ul_pdr(teid, ul_pdr_slice).await?;
        match (session.ue_ipv4(), session.ue_ipv6()) {
            (None, None) => bail!("session has no UE IP address, cannot compile"),
            (None, Some(_)) => {
                todo!()
            }
            (Some(ue_ipv4), None) => {
                self.maps
                    .insert_dl_pdr_ivp4(ue_ipv4.to_bits(), ul_pdr_slice)
                    .await?;
            }
            (Some(_), Some(_)) => {
                todo!()
            }
        };

        Ok(())
    }

    pub async fn send_to(&self, buf: &[u8], to: SocketAddr) -> Result<usize, std::io::Error> {
        self.socket.send_to(buf, to).await
    }

    pub async fn send_response(&self, bytes: &[u8], to: SocketAddr) -> anyhow::Result<()> {
        if let Ok(n) = self.send_to(bytes, to).await {
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
        while let Ok((len, addr)) = ctx.socket.recv_from(&mut buf).await {
            debug!("{:?} bytes received from {:?}", len, addr);
            match rs_pfcp::message::parse(&buf[..len]) {
                Ok(msg) => match msg.msg_type() {
                    MsgType::AssociationSetupRequest => {
                        debug!("incoming association setup request from {:?}", addr);
                        let req = AssociationSetupRequest::unmarshal(&buf[..len]).unwrap();
                        handle_association_setup_request(&ctx, &req, addr)
                            .await
                            .unwrap()
                    }
                    MsgType::HeartbeatRequest => handle_hearbeat_request().await.unwrap(),
                    MsgType::SessionEstablishmentRequest => {
                        debug!("incoming session establishment request from {:?}", addr);
                        let req = SessionEstablishmentRequest::unmarshal(&buf[..len]).unwrap();
                        handle_session_establishment_request(&ctx, &req, addr)
                            .await
                            .unwrap();
                    }
                    MsgType::SessionModificationRequest => {
                        debug!("incoming session modification request");
                        let req = SessionModificationRequest::unmarshal(&buf[..len]).unwrap();
                        handle_session_modification_request(&ctx, &req, addr)
                            .await
                            .unwrap();
                    }
                    MsgType::SessionDeletionRequest => {
                        todo!()
                    }
                    _ => debug!("unsupported message type received"),
                },
                Err(_) => todo!(),
            }
        }
    });

    Ok(())
}
