use log::debug;
use raxupf_common::far::{DestinationInterfacePod, FarInfo};
use rs_pfcp::ie::{create_far::CreateFar, destination_interface::Interface, update_far::UpdateFar};

use crate::{rules::helpers::ohc_description_to_flags, session::PfcpSession};

pub fn create_far_rule(received_far: CreateFar, session: &mut PfcpSession) -> anyhow::Result<()> {
    debug!("Incoming FAR: {:?}", received_far);
    let far_id = received_far.far_id.value;
    let mut far_info = FarInfo::default();

    // access octet 5, which contains all the basic flags
    let action = received_far.apply_action.octets()[0];
    far_info.set_action(action);

    if let Some(fp) = received_far.forwarding_parameters {
        let destination_interface = fp.destination_interface;
        let destination_interface = match destination_interface.interface {
            Interface::Access => DestinationInterfacePod::ACCESS,
            Interface::Core => DestinationInterfacePod::CORE,
            Interface::SgiLanN6Lan => DestinationInterfacePod::SGI_LAN_N6_LAN,
            Interface::CpFunction => DestinationInterfacePod::CP_FUNCTION,
            Interface::LiFunction => DestinationInterfacePod::LI_FUNCTION,
            Interface::FiveGvnInternal => DestinationInterfacePod::FIVE_GVN_INTERNAL,
        };
        far_info.set_destination_interface(destination_interface);

        if let Some(tlm) = fp.transport_level_marking {
            far_info.set_dscp(tlm.dscp);
        }

        if let Some(ohc) = fp.outer_header_creation {
            let teid = ohc.teid.unwrap();
            far_info.set_teid(teid.value());
            // TODO: do not hope for the best
            if let Some(remote_ipv4) = ohc.ipv4_address {
                far_info.set_remote_ipv4(remote_ipv4.to_bits());
            }
            if let Some(remote_ipv6) = ohc.ipv6_address {
                far_info.set_remote_ipv6(remote_ipv6.to_bits());
            }
            let flags = ohc_description_to_flags(ohc.description);
            far_info.set_ohc(flags);
        }
    }

    far_info.set_allocated(true);
    session.insert_far(far_id, far_info)
}

pub fn update_far_rule(received_far: UpdateFar, session: &mut PfcpSession) {
    debug!("Incoming FAR update: {:?}", received_far);
    let far_id = received_far.far_id.value;
    if let Some(far) = session.get_far_mut(far_id) {
        if let Some(apply_action) = received_far.apply_action {
            let action = apply_action.octets()[0];
            far.set_action(action);
        }

        if let Some(update_fp) = received_far.update_forwarding_parameters {
            if let Some(destination_interface) = update_fp.destination_interface {
                let destination_interface = match destination_interface.interface {
                    Interface::Access => DestinationInterfacePod::ACCESS,
                    Interface::Core => DestinationInterfacePod::CORE,
                    Interface::SgiLanN6Lan => DestinationInterfacePod::SGI_LAN_N6_LAN,
                    Interface::CpFunction => DestinationInterfacePod::CP_FUNCTION,
                    Interface::LiFunction => DestinationInterfacePod::LI_FUNCTION,
                    Interface::FiveGvnInternal => DestinationInterfacePod::FIVE_GVN_INTERNAL,
                };
                far.set_destination_interface(destination_interface);
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

pub fn remove_far_rule(session: &mut PfcpSession, far_id: u32) {}
