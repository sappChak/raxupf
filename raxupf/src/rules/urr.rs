use log::debug;
use raxupf_common::urr::UrrInfo;
use rs_pfcp::ie::{create_urr::CreateUrr, update_urr::UpdateUrr};

use crate::session::PfcpSession;

pub fn create_urr_rule(received_urr: CreateUrr, session: &mut PfcpSession) -> anyhow::Result<()> {
    debug!("Incoming URR: {:?}", received_urr);
    let mut urr_info = UrrInfo::default();
    urr_info.set_allocated(true);
    Ok(())
}

pub fn update_urr_rule(received_urr: UpdateUrr, session: &mut PfcpSession) {}

pub fn remove_urr_rule(urr_id: u32) {}
