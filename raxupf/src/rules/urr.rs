use log::debug;
use rs_pfcp::ie::{create_urr::CreateUrr, update_urr::UpdateUrr};

use crate::{
    iprule_parser::parse_sdf_filter, pfcp::PfcpContext, rules::helpers::ohc_description_to_flags,
    session::PfcpSession,
};

pub fn create_urr_rule(received_urr: CreateUrr, session: &mut PfcpSession) {
    debug!("Incoming URR: {:?}", received_urr);
}

pub fn update_urr_rule(received_urr: UpdateUrr, session: &mut PfcpSession) {}

pub fn remove_urr_rule(urr_id: u32) {}
