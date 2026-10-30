use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
};

use raxupf::{
    handlers::{
        handle_association_setup_request, handle_session_deletion_request,
        handle_session_establishment_request, handle_session_modification_request,
    },
    helpers::nodeid_from_str,
};
use rs_pfcp::{
    ie::{
        NodeId,
        apply_action::ApplyAction,
        bar_id::BarId,
        cause::{Cause, CauseValue},
        create_bar::CreateBar,
        create_far::CreateFar,
        create_qer::CreateQerBuilder,
        create_urr::CreateUrrBuilder,
        destination_interface::{DestinationInterface, Interface},
        far_id::FarId,
        forwarding_parameters::ForwardingParameters,
        gate_status::{GateStatus, GateStatusValue},
        measurement_method::MeasurementMethod,
        network_instance::NetworkInstance,
        outer_header_creation::OuterHeaderCreation,
        qer_id::QerId,
        qfi::Qfi,
        reporting_triggers::ReportingTriggers,
        source_interface::SourceInterfaceValue,
        three_gpp_interface_type::{ThreeGppInterfaceType, ThreeGppInterfaceTypeIe},
        update_far::UpdateFarBuilder,
        update_forwarding_parameters::UpdateForwardingParameters,
        urr_id::UrrId,
        volume_threshold::VolumeThreshold,
    },
    message::{
        Message, association_setup_request::AssociationSetupRequestBuilder,
        session_deletion_request::SessionDeletionRequestBuilder,
        session_establishment_request::SessionEstablishmentRequestBuilder,
        session_modification_request::SessionModificationRequestBuilder,
    },
};

use crate::{
    common::spawn_test_setup,
    helpers::{CreatePdrParams, create_downlink_pdr, create_uplink_pdr},
};

#[tokio::test]
async fn basic_pfcp_lifecycle_succeeds() -> anyhow::Result<()> {
    // Arrange
    let test_setup = spawn_test_setup().await.unwrap();
    let ctx = test_setup.ctx();
    let gnb_ipv4 = Ipv4Addr::from_str("172.20.0.140").unwrap();
    let (smf_ipv4, smf_port) = (Ipv4Addr::from_str("172.20.0.110").unwrap(), 8805);
    let smf_ip = IpAddr::V4(smf_ipv4);
    let smf_sock_addr = SocketAddr::V4(SocketAddrV4::new(smf_ipv4, smf_port));
    let nodeid_fqdn = "smf.open5gs.org";
    let ue_ipv4 = Ipv4Addr::from_str("10.60.0.2").unwrap();
    let ue_ip = IpAddr::V4(ue_ipv4);
    let smf_seid = 0x3a5u64;
    let dnn = "internet";

    let association_setup_request = AssociationSetupRequestBuilder::new(1)
        .node_id_fqdn(nodeid_fqdn)
        .recovery_time_stamp(std::time::SystemTime::now())
        .build();

    // Act
    let association_setup_response = handle_association_setup_request(
        test_setup.ctx(),
        &association_setup_request,
        smf_sock_addr,
    )
    .await?;

    // Assert
    assert_eq!(association_setup_response.sequence().0, 1);

    let upf_node_id = association_setup_response.node_id.parse::<NodeId>()?;
    let expected_node_id = nodeid_from_str(test_setup.ctx().node_id())?;
    assert_eq!(expected_node_id, upf_node_id);

    let cause = association_setup_response.cause.parse::<Cause>()?;
    assert_eq!(cause.value, CauseValue::RequestAccepted);
    // TODO: ensure UP features are correct

    // Arrange
    // 3GPP interface type IE is skipped
    let bar = CreateBar::new(BarId::new(1), None);
    let unknown_far = CreateFar::builder(FarId::new(1))
        .apply_action(ApplyAction::BUFF | ApplyAction::NOCP)
        .bar_id(bar.bar_id)
        .build()?;
    let uplink_far = CreateFar::builder(FarId::new(2))
        .forward_to_network(Interface::Core, NetworkInstance::new(dnn))
        .build()?;
    let cp_far = CreateFar::builder(FarId::new(3))
        .apply_action(ApplyAction::FORW)
        .forwarding_parameters(
            ForwardingParameters::new(DestinationInterface::new(Interface::CpFunction))
                .with_outer_header_creation(OuterHeaderCreation::gtpu_ipv4(1, smf_ipv4)),
        )
        .build()?;

    let mut reporting_triggers = ReportingTriggers::new();
    reporting_triggers.insert(ReportingTriggers::VOLTH);
    let urr = CreateUrrBuilder::new(UrrId::new(1))
        .measurement_method(MeasurementMethod::new(false, true, false))
        .reporting_triggers(reporting_triggers)
        .volume_threshold(VolumeThreshold::new(
            true,
            false,
            false,
            Some(104857600),
            None,
            None,
        ))
        .build()
        .unwrap();

    let qer = CreateQerBuilder::new(QerId::new(1))
        .gate_status(GateStatus::new(
            GateStatusValue::Open,
            GateStatusValue::Open,
        ))
        .rate_limit(1_000_000, 1_000_000) // 1Mbps up, 1Mbps down
        .qfi(Qfi::of(1))
        .build()
        .unwrap();

    let params = CreatePdrParams {
        pdr_id: 1,
        teid: None,
        smf_ip,
        ue_ip: Some(ue_ip),
        source_interface: SourceInterfaceValue::Core,
        dnn: dnn.to_string(),
        description: None,
        flow_description: None,
        precedence: 65535,
        far_id: unknown_far.far_id.value,
        qer_id: qer.qer_id.value,
        urr_id: urr.urr_id.id,
    };
    let downlink_pdr = create_downlink_pdr(&params)?;

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
        far_id: uplink_far.far_id.value,
        qer_id: qer.qer_id.value,
        urr_id: urr.urr_id.id,
    };
    let uplink_pdr = create_uplink_pdr(&params)?;

    let params = CreatePdrParams {
        pdr_id: 3,
        teid: Some(0x1d32),
        smf_ip,
        ue_ip: None,
        source_interface: SourceInterfaceValue::CpFunction,
        dnn: dnn.to_string(),
        description: Some(6), // GTPU_UDP_IP
        flow_description: None,
        precedence: 255,
        far_id: cp_far.far_id.value,
        qer_id: qer.qer_id.value,
        urr_id: urr.urr_id.id,
    };
    let cp_pdr = create_uplink_pdr(&params)?;

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
        far_id: unknown_far.far_id.value,
        qer_id: qer.qer_id.value,
        urr_id: urr.urr_id.id,
    };
    let icmpv6_pdr = create_uplink_pdr(&params)?;

    let session_estab_request = SessionEstablishmentRequestBuilder::new(0, 3)
        .node_id_fqdn(nodeid_fqdn)
        .fseid(smf_seid, smf_ipv4)
        .add_pdr(uplink_pdr)
        .add_pdr(downlink_pdr)
        .add_pdr(cp_pdr)
        .add_pdr(icmpv6_pdr)
        .add_far(unknown_far.clone())
        .add_far(uplink_far)
        .add_far(cp_far)
        .add_qer(qer)
        .add_urr(urr)
        .build()
        .unwrap();

    // Act
    let session_estab_response =
        handle_session_establishment_request(test_setup.ctx(), &session_estab_request).await?;

    // Assert
    assert_eq!(
        session_estab_response.cause()?.value,
        CauseValue::RequestAccepted
    );

    let upf_node_id = session_estab_response.node_id()?;
    assert_eq!(expected_node_id, upf_node_id);
    assert_eq!(session_estab_response.created_pdrs().len(), 4);

    let up_seid = session_estab_response.fseid().unwrap().seid.value();

    let _session = ctx.get_session(up_seid).await.unwrap();
    // TODO: ensure that all requested rules are stored
    // println!("{:?}", session);

    // Arrange
    let updated_downlink_far = UpdateFarBuilder::new(FarId::new(unknown_far.far_id.value))
        .apply_action(rs_pfcp::ie::apply_action::ApplyAction::FORW)
        .update_forwarding_parameters(
            UpdateForwardingParameters::new()
                .with_destination_interface(
                    rs_pfcp::ie::destination_interface::DestinationInterface::new(
                        Interface::Access,
                    ),
                )
                .with_network_instance(NetworkInstance::new(dnn))
                .with_outer_header_creation(OuterHeaderCreation::gtpu_ipv4(1, gnb_ipv4))
                .with_three_gpp_interface_type(ThreeGppInterfaceTypeIe::new(
                    ThreeGppInterfaceType::N3,
                )),
        )
        .build()?;

    let session_mod_request = SessionModificationRequestBuilder::new(up_seid, 4)
        .fseid(smf_seid, smf_ipv4)
        .update_fars(vec![updated_downlink_far.to_ie()])
        .build();

    // Act
    let response = handle_session_modification_request(ctx, &session_mod_request).await?;

    // Assert
    let cause = response.cause.parse::<Cause>()?;
    assert_eq!(cause.value, CauseValue::RequestAccepted);

    // Arrange
    let request = SessionDeletionRequestBuilder::new(up_seid, 4).build();

    // Act
    let response = handle_session_deletion_request(ctx, &request).await?;

    // Assert
    let cause = response.cause.parse::<Cause>()?;
    assert_eq!(cause.value, CauseValue::RequestAccepted);
    assert!(ctx.get_session(up_seid).await.is_none());

    Ok(())
}
