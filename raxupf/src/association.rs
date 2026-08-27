use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use log::{debug, warn};
use rs_pfcp::{
    ie::{cause::CauseValue, node_id::NodeId, recovery_time_stamp::RecoveryTimeStamp},
    message::{
        AssociationSetupRequest, Message,
        association_setup_response::AssociationSetupResponseBuilder,
    },
};
use tokio::{net::UdpSocket, sync::Mutex};

use crate::session::PfcpSession;

pub struct PfcpAssociation {
    node_id: String,
    addr: std::net::IpAddr,
    sessions: HashMap<u64, PfcpSession>,
    local_seid: u64,
}

impl PfcpAssociation {
    pub fn new(node_id: String, addr: std::net::IpAddr) -> Self {
        Self {
            node_id,
            addr,
            sessions: HashMap::default(),
            local_seid: 1,
        }
    }

    // inspired by eUPF
    pub fn local_seid(&mut self) -> u64 {
        self.local_seid += 1;
        self.local_seid
    }
}

pub async fn handle_association_setup_request(
    socket: &UdpSocket,
    buf: &[u8],
    len: usize,
    addr: SocketAddr,
    associations: Arc<Mutex<HashMap<String, PfcpAssociation>>>,
    node_id: &str,
    timestamp: std::time::SystemTime,
) {
    // message handling in accordance to 29.244, clause 6.2.6.2.2
    debug!("incoming association setup request");

    let req = AssociationSetupRequest::unmarshal(&buf[..len]).unwrap();

    let remote_nodeid = match req.node_id.parse::<NodeId>() {
        Ok(node_id) => match node_id {
            NodeId::IPv4(ipv4_addr) => ipv4_addr.to_string(),
            NodeId::IPv6(ipv6_addr) => ipv6_addr.to_string(),
            NodeId::FQDN(fqdn) => fqdn,
        },
        Err(_) => {
            warn!("error parsing node_id");
            todo!()
        }
    };
    debug!("remote node id is: {}", remote_nodeid);

    let _recovery: std::time::SystemTime =
        match req.recovery_time_stamp.parse::<RecoveryTimeStamp>() {
            Ok(rec_ts) => rec_ts.timestamp,
            Err(_) => {
                warn!("error parsing recovery timestamp");
                todo!()
            }
        };

    // shall store the Node ID of the CP function as the identifier of the PFCP association
    let mut associations = associations.lock().await;
    match associations.entry(remote_nodeid.clone()) {
        std::collections::hash_map::Entry::Occupied(mut e) => {
            // overwrite existing association
            let association = PfcpAssociation::new(remote_nodeid.clone(), addr.ip());
            e.insert(association);
            // TODO: there are 2 more "shall's" in the spec for this case
        }
        std::collections::hash_map::Entry::Vacant(e) => {
            let association = PfcpAssociation::new(remote_nodeid.clone(), addr.ip());
            e.insert_entry(association);
        }
    };

    let node_id = if let Ok(ip_v4) = node_id.parse::<Ipv4Addr>() {
        NodeId::IPv4(ip_v4)
    } else if let Ok(ip_v6) = node_id.parse::<Ipv6Addr>() {
        NodeId::IPv6(ip_v6)
    } else {
        NodeId::new_fqdn(node_id)
    };

    send_association_setup_response(socket, &req, &node_id, timestamp, addr).await;
}

async fn send_association_setup_response(
    socket: &UdpSocket,
    req: &AssociationSetupRequest,
    node_id: &NodeId,
    timestamp: std::time::SystemTime,
    addr: SocketAddr,
) {
    // TODO: information of all supported optional features in the UP function
    let response = AssociationSetupResponseBuilder::new(req.sequence())
        .cause(CauseValue::RequestAccepted)
        .node_id_ie(node_id.to_ie())
        .recovery_time_stamp(timestamp)
        .build();
    let bytes: Vec<u8> = response.marshal();
    if let Ok(n) = socket.send_to(&bytes, addr).await {
        debug!("sent {} bytes to {:?}", n, addr);
    };
}
