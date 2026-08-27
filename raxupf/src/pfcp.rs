use std::{collections::HashMap, sync::Arc, time::SystemTime};

use log::debug;
use rs_pfcp::message::{MsgType, header};
use tokio::{net::UdpSocket, sync::Mutex as TokioMutex};

use crate::{
    association::{PfcpAssociation, handle_association_setup_request},
    configuration::config::Configuration,
    heartbeat::handle_hearbeat_request,
    session::handle_session_establishment_request,
};

const PFCP_PORT: u16 = 8805; // 3GPP TS 29.244 Release 17, clause 4.2.2

pub struct PfcpServer {
    local_addr: String,
    node_id: String,
    recovery_ts: SystemTime,
    associations: Arc<TokioMutex<HashMap<String, PfcpAssociation>>>, // key: remote node_id
}

impl PfcpServer {
    pub fn new(configuration: &Configuration) -> Self {
        Self {
            local_addr: configuration.pfcp.addr.clone(),
            node_id: configuration.pfcp.node_id.clone(),
            recovery_ts: SystemTime::now(),
            associations: Arc::new(TokioMutex::new(HashMap::new())),
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let socket = UdpSocket::bind(format!("{}:{}", self.local_addr, PFCP_PORT)).await?;
        let mut buf = [0; 4048];

        let associations: Arc<TokioMutex<HashMap<String, PfcpAssociation>>> =
            Arc::clone(&self.associations);
        let node_id = self.node_id.clone();
        let timestamp = self.recovery_ts;
        tokio::task::spawn(async move {
            while let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                debug!("{:?} bytes received from {:?}", len, addr);
                match header::Header::unmarshal(&buf[..len]) {
                    Ok(header) => match header.message_type {
                        MsgType::AssociationSetupRequest => {
                            handle_association_setup_request(
                                &socket,
                                &buf,
                                len,
                                addr,
                                associations.clone(),
                                &node_id,
                                timestamp,
                            )
                            .await
                        }
                        MsgType::HeartbeatRequest => handle_hearbeat_request().await,
                        MsgType::SessionEstablishmentRequest => {
                            handle_session_establishment_request(
                                &socket,
                                &buf,
                                len,
                                addr,
                                associations.clone(),
                            )
                            .await
                        }
                        MsgType::SessionModificationRequest => {
                            todo!()
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
}
