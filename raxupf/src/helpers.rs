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

use crate::{iprule_parser::parse_sdf_filter, pfcp::PfcpContext, session::PfcpSession};

fn ohc_description_to_flags(desc: OuterHeaderCreationFlags) -> OhcFlags {
    let mut flags = OhcFlags::empty();
    if desc.gtpu_udp_ipv4 {
        flags |= OhcFlags::GTPU_UDP_IPV4;
    }
    if desc.gtpu_udp_ipv6 {
        flags |= OhcFlags::GTPU_UDP_IPV6;
    }
    if desc.udp_ipv4 {
        flags |= OhcFlags::UDP_IPV4;
    }
    if desc.udp_ipv6 {
        flags |= OhcFlags::UDP_IPV6;
    }
    if desc.ipv4 {
        flags |= OhcFlags::IPV4;
    }
    if desc.ipv6 {
        flags |= OhcFlags::IPV6;
    }
    if desc.ctag {
        flags |= OhcFlags::CTAG;
    }
    if desc.stag {
        flags |= OhcFlags::STAG;
    }
    flags
}

pub fn create_far_rule(received_far: CreateFar, session: &mut PfcpSession) {
    debug!("Incoming FAR: {:?}", received_far);
    let id = received_far.far_id.value;
    let mut info = FarInfo::new();

    // access octet 5, which contains all the basic flags
    let action = received_far.apply_action.octets()[0];
    info.set_action(action);

    match received_far.forwarding_parameters {
        Some(fp) => {
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
        None => {
            debug!("No forwarding parameters in the received FAR");
        }
    }
}

pub fn create_qer_rule(received_qer: CreateQer, session: &mut PfcpSession) {
    debug!("Incoming QER: {:?}", received_qer);
}

pub fn create_urr_rule(received_urr: CreateUrr, session: &mut PfcpSession) {
    debug!("Incoming URR: {:?}", received_urr);
}

pub async fn create_pdr_rule(
    received_pdr: CreatePdr,
    ctx: &PfcpContext,
    session: &mut PfcpSession,
) -> anyhow::Result<CreatedPdr> {
    debug!("Incoming PDR: {:?}", received_pdr);
    let pdr_id = received_pdr.pdr_id;
    let mut pdr_info = PdrInfo::new(pdr_id.value);
    pdr_info.set_pdr_id(pdr_id.value);
    pdr_info.set_precedence(received_pdr.precedence.value);

    if let Some(ohr) = received_pdr.outer_header_removal {
        pdr_info.set_ohr(ohr.description);
    }

    let mut pdi_pod = PdiPod::new();
    let source_interface: u8 = match received_pdr.pdi.source_interface.value {
        SourceInterfaceValue::Access => 0,
        SourceInterfaceValue::Core => 1,
        SourceInterfaceValue::SgiLan => 2,
        SourceInterfaceValue::CpFunction => 3,
        SourceInterfaceValue::Unknown => 4,
    };
    pdi_pod.set_source_interface(source_interface);

    let local_fteid: Option<Fteid> = if let Some(fteid) = received_pdr.pdi.f_teid {
        if fteid.ch {
            if fteid.chid {
                match ctx.allocate_local_fteid_chid(fteid.choose_id).await {
                    Ok(fteid) => {
                        // only ipv4 for now
                        let fteid_pod = FteidPod::new(
                            fteid.ipv4_address.unwrap().to_bits(),
                            fteid.teid.value(),
                        );
                        pdi_pod.set_fteid(fteid_pod);
                        Some(fteid)
                    }
                    Err(e) => {
                        bail!(
                            "Failed to allocate F-TEID with CHOOSE ID {} for PDR {}: {e}",
                            fteid.chid,
                            pdr_id.value
                        );
                    }
                }
            } else {
                match ctx.allocate_local_fteid().await {
                    Ok(fteid) => {
                        // only ipv4 for now
                        let fteid_pod = FteidPod::new(
                            fteid.ipv4_address.unwrap().to_bits(),
                            fteid.teid.value(),
                        );
                        pdi_pod.set_fteid(fteid_pod);
                        Some(fteid)
                    }
                    Err(e) => {
                        bail!("Failed to allocate F-TEID for PDR {}: {e}", pdr_id.value);
                    }
                }
            }
        } else if fteid.v4 || fteid.v6 {
            // only ipv4 for now
            debug!("F-TEID is already allocated");
            let fteid_pod =
                FteidPod::new(fteid.ipv4_address.unwrap().to_bits(), fteid.teid.value());
            pdi_pod.set_fteid(fteid_pod);
            None // F-TEID is pre-allocated
        } else {
            None // F-TEID is not allocated
        }
    } else {
        None
    };

    // TODO: add support for IP6PL feature
    let ue_ip: Option<UeIpAddress> = if !received_pdr.pdi.ue_ip_addresses.is_empty() {
        let ue_ip = &received_pdr.pdi.ue_ip_addresses[0];
        if ue_ip.choose_ipv4 || ue_ip.choose_ipv6 {
            let ue_ip_address = ctx.allocate_ue_ip().await?;
            Some(ue_ip_address)
        } else if ue_ip.v4 || ue_ip.v6 {
            debug!(
                "UE IP address is already allocated: {:?}",
                ue_ip.ipv4_address.unwrap()
            );
            pdi_pod.set_ue_ipv4_address(ue_ip.ipv4_address.unwrap().to_bits());
            None // UE IP is pre-allocated
        } else {
            None // UE IP is neither allocated nor present in the PDI
        }
    } else {
        None
    };

    for (idx, qfi) in received_pdr.pdi.qfis.iter().enumerate() {
        if idx < MAX_QFI_NUM {
            pdi_pod.set_qfi(idx, qfi.value());
        } else {
            error!("Exceeded maximum number of QFIs in a PDI");
            break;
        }
    }

    for (idx, sdf) in received_pdr.pdi.sdf_filters.iter().enumerate() {
        let mut sdf_pod = parse_sdf_filter(sdf)?;
        sdf_pod.set_allocated(true);
        pdi_pod.set_sdf(idx, sdf_pod);
    }

    pdr_info.set_pdi(pdi_pod);

    if let Some(far_id) = received_pdr.far_id {
        pdr_info.set_far_id(far_id.value);
    }

    for (idx, qer_id) in received_pdr.qer_ids.iter().enumerate() {
        pdr_info.set_qer_id(idx, qer_id.value);
    }

    for (idx, urr_id) in received_pdr.urr_ids.iter().enumerate() {
        pdr_info.set_urr_id(idx, urr_id.id);
    }

    pdr_info.set_allocated(true);

    // Provide things that were requested to be allocated back to SMF
    let created_pdr = match (local_fteid, ue_ip) {
        (Some(f_teid), Some(ue_ip_address)) => CreatedPdr::new(pdr_id)
            .f_teid(f_teid)
            .ue_ip_address(ue_ip_address),
        (Some(f_teid), None) => CreatedPdr::new(pdr_id).f_teid(f_teid),
        (None, Some(ue_ip)) => CreatedPdr::new(pdr_id).ue_ip_address(ue_ip),
        (None, None) => CreatedPdr::new(pdr_id),
    };

    if pdr_info.pdi().pdi_mask().contains(PdiMask::UE_IPV4) {
        session.insert_dl_pdr(pdr_info.pdr_id(), pdr_info);
    } else {
        session.insert_ul_pdr(pdr_info.pdr_id(), pdr_info);
    }

    Ok(created_pdr)
}

pub fn remove_far_rule(far_id: u32) {}

pub fn remove_qer_rule(qer_id: u32) {}

pub fn remove_urr_rule(urr_id: u32) {}

pub fn remove_pdr_rule(pdr_id: u16) {}

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

pub fn update_qer_rule(received_qer: UpdateQer, session: &mut PfcpSession) {}

pub fn update_urr_rule(received_urr: UpdateUrr, session: &mut PfcpSession) {}

pub async fn update_pdr_rule(
    update_pdr: UpdatePdr,
    ctx: &PfcpContext,
    session: &mut PfcpSession,
) -> anyhow::Result<()> {
    debug!("Incoming PDR update: {:?}", update_pdr);
    let pdr_id = update_pdr.pdr_id.value;

    if let Some(pdr_info) = session.ul_pdrs.get_mut(&pdr_id) {
        if let Some(precedence) = update_pdr.precedence {
            debug!(
                "Updating precedence for PDR {}: {}",
                pdr_id, precedence.value
            );
            pdr_info.set_precedence(precedence.value);
        }

        if let Some(ohr) = update_pdr.outer_header_removal {
            debug!("Updating OHR for PDR {}: {:?}", pdr_id, ohr.description);
            pdr_info.set_ohr(ohr.description);
        }

        // if let Some(source_interface) = update_pdr
        if let Some(pdi) = update_pdr.pdi {
            debug!("Updating PDI for PDR {}: {:?}", pdr_id, pdi);
            let mut pdi_pod = pdr_info.pdi();

            if let Some(fteid) = pdi.f_teid {
                debug!("Updating F-TEID for PDR {}: {:?}", pdr_id, fteid);
                if fteid.ch {
                    if fteid.chid {
                        debug!(
                            "Allocating F-TEID with CHOOSE ID {} for PDR {}",
                            fteid.choose_id, pdr_id
                        );
                        match ctx.allocate_local_fteid_chid(fteid.choose_id).await {
                            Ok(fteid) => {
                                // only ipv4 for now
                                let fteid_pod = FteidPod::new(
                                    fteid.ipv4_address.unwrap().to_bits(),
                                    fteid.teid.value(),
                                );
                                pdi_pod.set_fteid(fteid_pod);
                                Some(fteid)
                            }
                            Err(e) => {
                                bail!(
                                    "Failed to allocate F-TEID with CHOOSE ID {} for PDR {}: {e}",
                                    fteid.chid,
                                    pdr_id
                                );
                            }
                        }
                    } else {
                        debug!("Allocating F-TEID without CHOOSE ID for PDR {}", pdr_id);
                        match ctx.allocate_local_fteid().await {
                            Ok(fteid) => {
                                // only ipv4 for now
                                let fteid_pod = FteidPod::new(
                                    fteid.ipv4_address.unwrap().to_bits(),
                                    fteid.teid.value(),
                                );
                                pdi_pod.set_fteid(fteid_pod);
                                Some(fteid)
                            }
                            Err(e) => {
                                bail!("Failed to allocate F-TEID for PDR {}: {e}", pdr_id);
                            }
                        }
                    }
                } else if fteid.v4 || fteid.v6 {
                    // only ipv4 for now
                    debug!("F-TEID is already allocated");
                    let fteid_pod =
                        FteidPod::new(fteid.ipv4_address.unwrap().to_bits(), fteid.teid.value());
                    pdi_pod.set_fteid(fteid_pod);
                    None // F-TEID is pre-allocated
                } else {
                    None // F-TEID is not allocated
                }
            } else {
                None
            };

            // TODO: add support for IP6PL feature
            if !pdi.ue_ip_addresses.is_empty() {
                debug!(
                    "Updating UE IP address for PDR {}: {:?}",
                    pdr_id, pdi.ue_ip_addresses
                );
                let ue_ip = &pdi.ue_ip_addresses[0];
                if ue_ip.choose_ipv4 || ue_ip.choose_ipv6 {
                    let ue_ip_address = ctx.allocate_ue_ip().await?;
                    Some(ue_ip_address)
                } else if ue_ip.v4 || ue_ip.v6 {
                    debug!(
                        "UE IP address is already allocated: {:?}",
                        ue_ip.ipv4_address.unwrap()
                    );
                    pdi_pod.set_ue_ipv4_address(ue_ip.ipv4_address.unwrap().to_bits());
                    None // UE IP is pre-allocated
                } else {
                    None // UE IP is neither allocated nor present in the PDI
                }
            } else {
                None
            };

            for (idx, qfi) in pdi.qfis.iter().enumerate() {
                if idx < MAX_QFI_NUM {
                    pdi_pod.set_qfi(idx, qfi.value());
                } else {
                    error!("Exceeded maximum number of qfis in a PDI");
                    break;
                }
            }

            for sdf in pdi.sdf_filters {
                // TODO: parse sdf filter
                debug!("SDF flow description in PDR: {}", sdf.flow_description);
            }

            pdr_info.set_pdi(pdi_pod);
        }

        if let Some(far_id) = update_pdr.far_id {
            debug!("Updating FAR ID for PDR {}: {}", pdr_id, far_id.value);
            pdr_info.set_far_id(far_id.value);
        }

        for (idx, qer_id) in update_pdr.qer_ids.iter().enumerate() {
            pdr_info.set_qer_id(idx, qer_id.value);
        }

        for (idx, urr_id) in update_pdr.urr_ids.iter().enumerate() {
            pdr_info.set_urr_id(idx, urr_id.id);
        }

        pdr_info.set_allocated(true);
    }

    Ok(())
}
