use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::SystemTime,
};

use aya::Ebpf;
use log::debug;
use raxupf_common::far::FarInfo;
use rs_pfcp::{
    error::PfcpError,
    ie::{f_teid::Fteid, ue_ip_address::UeIpAddress},
    message::{
        AssociationSetupRequest, Message, MsgType, SessionEstablishmentRequest,
        SessionModificationRequest,
    },
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
    session::{handle_session_establishment_request, handle_session_modification_request},
};

const PFCP_PORT: u16 = 8805; // 3GPP TS 29.244 Release 17, clause 4.2.2

pub struct PfcpContext {
    socket: UdpSocket,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    node_id: String,
    recovery_ts: SystemTime,
    associations: RwLock<HashMap<String, PfcpAssociation>>, // key: remote node_id
    maps: BpfMaps,
    gtp_addr_v4: Ipv4Addr,
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
            local_addr,
            remote_addr,
            node_id: configuration.pfcp.node_id.clone(),
            recovery_ts: SystemTime::now(),
            associations: RwLock::new(HashMap::new()),
            maps: BpfMaps::new(ebpf)?,
            gtp_addr_v4: configuration.gtpu.addr.parse::<Ipv4Addr>()?,
            resource_manager: Mutex::new(ResourceManager::new()),
        }))
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn gtp_addr_v4(&self) -> Ipv4Addr {
        self.gtp_addr_v4
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

    pub async fn with_association<F, R>(&self, rnode_id: &str, f: F) -> Option<R>
    where
        F: Fn(&PfcpAssociation) -> R,
    {
        let association = self.associations.write().await;
        association.get(rnode_id).map(f)
    }

    pub async fn contains_association(&self, key: &str) -> bool {
        self.associations.read().await.contains_key(key)
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

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, std::io::Error> {
        self.socket.send_to(buf, addr).await
    }

    pub async fn send_response(&self, bytes: &[u8], addr: SocketAddr) -> anyhow::Result<()> {
        if let Ok(n) = self.send_to(bytes, addr).await {
            debug!("sent {} bytes to {:?}", n, addr);
        };
        Ok(())
    }

    pub async fn insert_far(&self, id: u32, info: FarInfo) -> anyhow::Result<()> {
        self.maps.fars.lock().await.insert(id, info, 0)?;
        Ok(())
    }

    pub async fn allocate_local_fteid(&self) -> Result<Fteid, PfcpError> {
        self.resource_manager.lock().await.allocate_local_fteid()
    }

    pub async fn allocate_local_fteid_chid(&self, choose_id: u8) -> Result<Fteid, PfcpError> {
        self.resource_manager
            .lock()
            .await
            .allocate_local_fteid_chid(choose_id)
    }

    pub async fn allocate_ue_ip(&self) -> Result<UeIpAddress, PfcpError> {
        self.resource_manager.lock().await.allocate_ue_ip()
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
