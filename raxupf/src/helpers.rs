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

pub fn prefix_to_ipv4_mask(prefix: u8) -> anyhow::Result<u32> {
    if prefix > 32 {
        return Err(anyhow::anyhow!("Invalid IPv4 prefix length: {}", prefix));
    }
    let mask = if prefix == 0 {
        0
    } else {
        (!0u32) << (32 - prefix)
    };
    Ok(mask)
}

pub fn prefix_to_ipv6_mask(prefix: u8) -> anyhow::Result<u128> {
    if prefix > 128 {
        return Err(anyhow::anyhow!("Invalid IPv6 prefix length: {}", prefix));
    }
    let mask = if prefix == 0 {
        0
    } else {
        (!0u128) << (128 - prefix)
    };
    Ok(mask)
}
