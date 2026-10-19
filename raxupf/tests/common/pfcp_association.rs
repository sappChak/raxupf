use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
};

use raxupf::{handlers::handle_association_setup_request, loader::load_ebpf};
use rs_pfcp::{
    ie::{
        NodeId,
        cause::{Cause, CauseValue},
    },
    message::{
        AssociationSetupRequest, Message, association_setup_request::AssociationSetupRequestBuilder,
    },
};

use crate::common::{CONFIGURATION, test_setup};

#[tokio::test]
async fn association_works() {
    let mut ebpf = load_ebpf().await.unwrap();
    let test_setup = test_setup(&mut ebpf).await.unwrap();
    let ctx = test_setup.ctx;
    let remote_addr = SocketAddr::V4(SocketAddrV4::from_str("172.20.0.110:8805").unwrap());
    let sequence_number = 8;

    let req: AssociationSetupRequest = AssociationSetupRequestBuilder::new(sequence_number)
        .node_id_fqdn("smf.open5gs.org")
        .recovery_time_stamp(std::time::SystemTime::now())
        .build();

    let response = handle_association_setup_request(&ctx, &req, remote_addr)
        .await
        .expect("Failed to handle Association Setup Request");
    assert_eq!(sequence_number, response.sequence().0);

    let node_id = response
        .node_id
        .parse::<NodeId>()
        .expect("Failed to parse NodeId IE");

    let ctx_node_id = ctx.node_id();
    let expected_node_id = if let Ok(ip_v4) = ctx_node_id.parse::<Ipv4Addr>() {
        NodeId::IPv4(ip_v4)
    } else if let Ok(ip_v6) = ctx_node_id.parse::<Ipv6Addr>() {
        NodeId::IPv6(ip_v6)
    } else {
        NodeId::new_fqdn(ctx_node_id)
    };

    assert_eq!(expected_node_id, node_id);

    let cause = response
        .cause
        .parse::<Cause>()
        .expect("Failed to parse Cause IE");
    assert_eq!(CauseValue::RequestAccepted, cause.value);
}
