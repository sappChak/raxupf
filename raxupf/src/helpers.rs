use std::net::{Ipv4Addr, Ipv6Addr};

use rs_pfcp::ie::NodeId;

pub fn nodeid_from_str(nodeid: &str) -> anyhow::Result<NodeId> {
    let node_id = if let Ok(ip_v4) = nodeid.parse::<Ipv4Addr>() {
        NodeId::IPv4(ip_v4)
    } else if let Ok(ip_v6) = nodeid.parse::<Ipv6Addr>() {
        NodeId::IPv6(ip_v6)
    } else {
        NodeId::new_fqdn(nodeid)
    };
    Ok(node_id)
}
