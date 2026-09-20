use std::net::{IpAddr, Ipv4Addr};

use anyhow::bail;
use log::{debug, error};
use raxupf_common::{
    MAX_QFI_NUM,
    far::{FarInfo, OhcFlags},
    fteid::FteidPod,
    pdi::{PdiMask, PdiPod},
    pdr::PdrInfo,
};
use rs_pfcp::ie::{
    create_far::CreateFar, create_pdr::CreatePdr, create_qer::CreateQer, create_urr::CreateUrr,
    created_pdr::CreatedPdr, f_teid::Fteid, outer_header_creation::OuterHeaderCreationFlags,
    source_interface::SourceInterfaceValue, ue_ip_address::UeIpAddress, update_far::UpdateFar,
    update_pdr::UpdatePdr, update_qer::UpdateQer, update_urr::UpdateUrr,
};

use crate::{
    iprule_parser::parse_sdf_filter, pfcp::PfcpContext, rules::helpers::ohc_description_to_flags,
    session::PfcpSession,
};

pub fn create_qer_rule(received_qer: CreateQer, session: &mut PfcpSession) {
    debug!("Incoming QER: {:?}", received_qer);
}

pub fn update_qer_rule(received_qer: UpdateQer, session: &mut PfcpSession) {}


pub fn remove_qer_rule(qer_id: u32) {}
