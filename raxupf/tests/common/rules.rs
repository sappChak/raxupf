use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use raxupf::{rules::pdr::create_pdr_rule, session::PfcpSession};
use raxupf_common::{
    SDF_MAP_SIZE,
    fteid::FteidPod,
    pdi::{PdiMask, PdiPod, SourceInterfacePod},
    pdr::{OhrPod, PdrInfo},
    sdf::{IpPod, SdfFilterPod},
};
use rs_pfcp::ie::source_interface::SourceInterfaceValue;

use crate::{
    common::spawn_test_setup,
    helpers::{CreatePdrParams, create_uplink_pdr},
};

#[tokio::test]
async fn session_contains_correct_ul_pdr() -> anyhow::Result<()> {
    // Arrange
    let test_setup = spawn_test_setup().await?;
    let ctx = test_setup.ctx();
    let smf_ipv4 = Ipv4Addr::from_str("172.20.0.110").unwrap();
    let dnn = "internet";
    let smf_ip = IpAddr::V4(smf_ipv4);

    let mut session = PfcpSession::new("smf.open5gs.org".to_string(), 12345);
    let params = CreatePdrParams {
        pdr_id: 2,
        teid: Some(0x500a),
        smf_ip,
        ue_ip: None,
        source_interface: SourceInterfaceValue::Access,
        dnn: dnn.to_string(),
        description: Some(6), // GTPU_UDP_IP
        flow_description: None,
        precedence: 65535,
        far_id: 0,
        qer_id: 0,
        urr_id: 0,
    };
    let received_pdr = create_uplink_pdr(&params)?;

    // Act
    let _ = create_pdr_rule(&received_pdr, ctx, &mut session).await?;

    // Assert
    let expected_pdi = PdiPod {
        pdi_mask: PdiMask::F_TEID,
        source_interface: SourceInterfacePod::ACCESS,
        fteid: FteidPod::new(
            0x500a,
            smf_ipv4.to_bits(),
            Ipv6Addr::UNSPECIFIED.octets(),
            true,
            false,
        ),
        ..Default::default()
    };
    let expected_pdr = PdrInfo {
        pdr_id: 2,
        precedence: 65535,
        outer_header_removal: OhrPod::GTPU_UDP_IP,
        pdi: expected_pdi,
        allocated: true,
        ..Default::default()
    };

    assert_eq!(*session.get_ul_pdr(2).unwrap(), expected_pdr);

    let params = CreatePdrParams {
        pdr_id: 4,
        teid: Some(0x500a),
        smf_ip,
        ue_ip: None,
        source_interface: SourceInterfaceValue::CpFunction,
        dnn: dnn.to_string(),
        description: Some(6), // GTPU_UDP_IP
        flow_description: Some("permit out 58 from ff02::2/128 to assigned".to_string()),
        precedence: 255,
        far_id: 0,
        qer_id: 0,
        urr_id: 0,
    };
    let icmpv6_pdr = create_uplink_pdr(&params)?;

    let _ = create_pdr_rule(&icmpv6_pdr, ctx, &mut session).await?;

    let expected_sdf = SdfFilterPod {
        protocol: 58,
        src_ip: IpPod::new(6, Ipv6Addr::from_str("ff02::2")?.to_bits(), 128),
        allocated: true,
        ..Default::default()
    };
    let mut expected_sdfs = [SdfFilterPod::default(); SDF_MAP_SIZE];
    expected_sdfs[0] = expected_sdf;
    let expected_pdi = PdiPod {
        pdi_mask: PdiMask::F_TEID,
        source_interface: SourceInterfacePod::CP_FUNCTION,
        fteid: FteidPod::new(
            0x500a,
            smf_ipv4.to_bits(),
            Ipv6Addr::UNSPECIFIED.octets(),
            true,
            false,
        ),
        sdfs: expected_sdfs,
        ..Default::default()
    };
    let expected_pdr = PdrInfo {
        pdr_id: 4,
        precedence: 255,
        outer_header_removal: OhrPod::GTPU_UDP_IP,
        pdi: expected_pdi,
        allocated: true,
        ..Default::default()
    };

    assert_eq!(*session.get_ul_pdr(4).unwrap(), expected_pdr);

    Ok(())
}
