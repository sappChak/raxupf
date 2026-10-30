use std::net::IpAddr;

use rs_pfcp::ie::{
    create_far::CreateFar,
    create_pdr::{CreatePdr, CreatePdrBuilder},
    f_teid::FteidBuilder,
    far_id::FarId,
    forwarding_parameters::ForwardingParameters,
    network_instance::NetworkInstance,
    outer_header_removal::OuterHeaderRemoval,
    pdi::PdiBuilder,
    pdr_id::PdrId,
    precedence::Precedence,
    qer_id::QerId,
    sdf_filter::SdfFilter,
    source_interface::{SourceInterface, SourceInterfaceValue},
    three_gpp_interface_type::{ThreeGppInterfaceType, ThreeGppInterfaceTypeIe},
    ue_ip_address::UeIpAddress,
    urr_id::UrrId,
};

pub struct CreatePdrParams {
    pub pdr_id: u16,
    pub teid: Option<u32>,
    pub smf_ip: IpAddr,
    pub ue_ip: Option<IpAddr>,
    pub source_interface: SourceInterfaceValue,
    pub dnn: String,
    pub description: Option<u8>,
    pub flow_description: Option<String>,
    pub precedence: u32,
    pub far_id: u32,
    pub qer_id: u32,
    pub urr_id: u32,
}

pub fn create_uplink_pdr(params: &CreatePdrParams) -> anyhow::Result<CreatePdr> {
    let uplink_fteid = FteidBuilder::new().teid(params.teid.unwrap());
    let uplink_fteid = match params.smf_ip {
        IpAddr::V4(ipv4_addr) => uplink_fteid.ipv4(ipv4_addr).build().unwrap(),
        IpAddr::V6(ipv6_addr) => uplink_fteid.ipv6(ipv6_addr).build().unwrap(),
    };

    let mut uplink_pdi = PdiBuilder::new(SourceInterface::new(params.source_interface))
        .f_teid(uplink_fteid)
        .network_instance(NetworkInstance::new(&params.dnn))
        .build()
        .unwrap();

    if let Some(flow_description) = &params.flow_description {
        uplink_pdi
            .sdf_filters
            .push(SdfFilter::new(flow_description));
    }

    // Create structured PDR for uplink traffic detection using builder pattern
    let uplink_pdr = CreatePdrBuilder::new(PdrId::new(params.pdr_id))
        .precedence(Precedence::new(params.precedence))
        .outer_header_removal(OuterHeaderRemoval::new(params.description.unwrap()))
        .pdi(uplink_pdi)
        .far_id(FarId::new(params.far_id))
        .qer_id(QerId::new(params.qer_id))
        .build()
        .unwrap();

    Ok(uplink_pdr)
}

pub fn create_downlink_pdr(params: &CreatePdrParams) -> anyhow::Result<CreatePdr> {
    let mut ue_ip: UeIpAddress = match params.ue_ip.unwrap() {
        IpAddr::V4(ipv4_addr) => UeIpAddress::new(Some(ipv4_addr), None),
        IpAddr::V6(ipv6_addr) => UeIpAddress::new(None, Some(ipv6_addr)),
    };
    ue_ip.source_destination = true;

    let downlink_pdi = PdiBuilder::downlink_core()
        .ue_ip_address(ue_ip)
        .network_instance(NetworkInstance::new(&params.dnn))
        .three_gpp_interface_type(ThreeGppInterfaceTypeIe::new(ThreeGppInterfaceType::N6))
        .build()
        .unwrap();

    let downlink_pdr = CreatePdrBuilder::new(PdrId::new(params.pdr_id))
        .precedence(Precedence::new(params.precedence))
        .pdi(downlink_pdi)
        .far_id(FarId::new(params.far_id))
        .qer_id(QerId::new(params.qer_id))
        .urr_id(UrrId::new(params.urr_id))
        .build()
        .unwrap();

    Ok(downlink_pdr)
}

pub fn create_far(far_id: u32, params: ForwardingParameters) -> anyhow::Result<CreateFar> {
    let far = CreateFar::builder(FarId::new(far_id))
        .forwarding_parameters(params)
        .build()
        .unwrap();
    Ok(far)
}
