use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use log::{debug, warn};
use rs_pfcp::{
    ie::{cause::CauseValue, node_id::NodeId, recovery_time_stamp::RecoveryTimeStamp},
    message::{
        AssociationSetupRequest, Message,
        association_setup_response::AssociationSetupResponseBuilder,
    },
};

use crate::pfcp::PfcpContext;

pub struct PfcpAssociation {
    lnode_id: String,
    laddr: std::net::IpAddr,
    lseid: u64,
}

impl PfcpAssociation {
    pub fn new(lnode_id: String, laddr: std::net::IpAddr) -> Self {
        Self {
            lnode_id,
            laddr,
            lseid: 1,
        }
    }

    pub fn lnode_id(&self) -> &str {
        &self.lnode_id
    }

    pub fn laddr(&self) -> std::net::IpAddr {
        self.laddr
    }

    pub fn allocate_up_seid(&mut self) -> u64 {
        self.lseid += 1;
        self.lseid
    }
}

pub async fn handle_association_setup_request(
    ctx: &PfcpContext,
    req: &AssociationSetupRequest,
    remote_addr: SocketAddr,
) -> anyhow::Result<()> {
    // message handling in accordance to 29.244, clause 6.2.6.2.2

    let rnode_id = match req.node_id.parse::<NodeId>() {
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
    debug!("remote node id is: {}", rnode_id);

    let _recovery: std::time::SystemTime =
        match req.recovery_time_stamp.parse::<RecoveryTimeStamp>() {
            Ok(rec_ts) => rec_ts.timestamp,
            Err(_) => {
                warn!("error parsing recovery timestamp");
                todo!()
            }
        };

    // shall store the Node ID of the CP function as the identifier of the PFCP association
    let association = PfcpAssociation::new(rnode_id.clone(), ctx.cp_addr().ip());
    let _ = ctx.insert_association(&rnode_id, association).await;

    let node_id = ctx.node_id();
    let node_id = if let Ok(ip_v4) = node_id.parse::<Ipv4Addr>() {
        NodeId::IPv4(ip_v4)
    } else if let Ok(ip_v6) = node_id.parse::<Ipv6Addr>() {
        NodeId::IPv6(ip_v6)
    } else {
        NodeId::new_fqdn(node_id)
    };

    // TODO: information of all supported optional features in the UP function
    let response = AssociationSetupResponseBuilder::new(req.sequence())
        .cause(CauseValue::RequestAccepted)
        .node_id_ie(node_id.to_ie())
        .recovery_time_stamp(ctx.recovery_ts())
        .build();

    ctx.send_response(&response.marshal(), remote_addr).await
}
