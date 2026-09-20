use log::debug;
use raxupf_common::far::FarInfo;
use rs_pfcp::ie::{create_far::CreateFar, update_far::UpdateFar};

use crate::{rules::helpers::ohc_description_to_flags, session::PfcpSession};

pub fn create_far_rule(received_far: CreateFar, session: &mut PfcpSession) {
    debug!("Incoming FAR: {:?}", received_far);
    let id = received_far.far_id.value;
    let mut info = FarInfo::new();

    // access octet 5, which contains all the basic flags
    let action = received_far.apply_action.octets()[0];
    info.set_action(action);

    if let Some(fp) = received_far.forwarding_parameters {
        let destination_interface = fp.destination_interface;
        info.set_destination_interface(destination_interface.interface.into());

        if let Some(tlm) = fp.transport_level_marking {
            info.set_dscp(tlm.dscp);
        }

        if let Some(ohc) = fp.outer_header_creation {
            let teid = ohc.teid.unwrap();
            info.set_teid(teid.value());
            let remote_ip = ohc.ipv4_address.unwrap();
            info.set_remote_ipv4(remote_ip.to_bits());
            let flags = ohc_description_to_flags(ohc.description);
            info.set_ohc(flags);
        }

        session.insert_far(id, info);
    }
}

pub fn update_far_rule(received_far: UpdateFar, session: &mut PfcpSession) {
    debug!("Incoming FAR update: {:?}", received_far);
    let far_id = received_far.far_id.value;
    if let Some(far) = session.fars.get_mut(&far_id) {
        if let Some(apply_action) = received_far.apply_action {
            let action = apply_action.octets()[0];
            far.set_action(action);
        }

        if let Some(update_fp) = received_far.update_forwarding_parameters {
            if let Some(destination_interface) = update_fp.destination_interface {
                far.set_destination_interface(destination_interface.interface.into());
            }

            if let Some(update_tlm) = update_fp.transport_level_marking {
                far.set_dscp(update_tlm.dscp);
            }

            if let Some(update_ohc) = update_fp.outer_header_creation {
                if let Some(teid) = update_ohc.teid {
                    far.set_teid(teid.value());
                }

                if let Some(remote_ip) = update_ohc.ipv4_address {
                    far.set_remote_ipv4(remote_ip.to_bits());
                }

                let flags = ohc_description_to_flags(update_ohc.description);
                far.set_ohc(flags);
            }
        }
    }
}

pub fn remove_far_rule(far_id: u32) {}
