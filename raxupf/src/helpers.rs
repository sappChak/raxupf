use anyhow::bail;
use log::{debug, error};
use raxupf_common::{
    MAX_QFI_NUM, SessionContextPod,
    far::{FarInfo, OhcFlags},
    fteid::FteidPod,
    pdi::{PdiMask, PdiPod},
    pdr::PdrInfo,
    qer::QerInfo,
    urr::UrrInfo,
};
use rs_pfcp::{
    error::PfcpError,
    ie::{
        Ie, cause::CauseValue, create_far::CreateFar, create_pdr::CreatePdr, create_qer::CreateQer,
        create_urr::CreateUrr, created_pdr::CreatedPdr, f_teid::Fteid, fseid::Fseid,
        node_id::NodeId, outer_header_creation::OuterHeaderCreationFlags, pdi::Pdi,
        remove_far::RemoveFar, remove_pdr::RemovePdr, remove_qer::RemoveQer,
        source_interface::SourceInterfaceValue, ue_ip_address::UeIpAddress, update_pdr::UpdatePdr,
        update_qer::UpdateQer,
    },
    message::{
        Message, SessionEstablishmentRequest, SessionModificationRequest,
        SessionModificationResponse,
        session_establishment_response::SessionEstablishmentResponseBuilder,
    },
};

use crate::{pfcp::PfcpContext, session::PfcpSession};

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

pub async fn create_rules(
    ctx: &PfcpContext,
    req: &SessionEstablishmentRequest,
    session: &mut PfcpSession,
) -> anyhow::Result<Vec<Ie>> {
    // TODO: implement rollback on failure
    debug!("Processing {} CreateFar IEs", req.create_fars.len());
    for (idx, create_far) in req.create_fars.iter().enumerate() {
        match create_far.parse::<CreateFar>() {
            Ok(received_far) => {
                debug!(
                    "    CreateFar {}: FAR ID: {}",
                    idx + 1,
                    received_far.far_id.value,
                );
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
            Err(_) => {
                bail!("Error extracting CreateFAR");
            }
        }
    }

    debug!("Processing {} CreateQer ies", req.create_qers.len());
    for create_qer in &req.create_qers {
        let _qer = match create_qer.parse::<CreateQer>() {
            Ok(qer) => qer,
            Err(_) => {
                bail!("Error extracting CreateQER");
            }
        };
    }

    debug!("Processing {} CreateUrr ies", req.create_urrs.len());
    for create_urr in &req.create_urrs {
        let _urr = match create_urr.parse::<CreateUrr>() {
            Ok(urr) => urr,
            Err(_) => {
                bail!("Error extracting CreateUrr");
            }
        };
    }

    debug!("Processing {} CreatePdr ies", req.create_pdrs.len());
    let mut created_pdrs: Vec<Ie> = Vec::new();
    for (idx, create_pdr_ie) in req.create_pdrs.iter().enumerate() {
        match create_pdr_ie.parse::<CreatePdr>() {
            Ok(received_pdr) => {
                let pdr_id = received_pdr.pdr_id;
                debug!(
                    "CreatePdr: {} PDR: {}, Precedence: {}",
                    idx + 1,
                    pdr_id.value,
                    received_pdr.precedence.value
                );
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
                                    bail!(
                                        "Failed to allocate F-TEID for PDR {}: {e}",
                                        pdr_id.value
                                    );
                                }
                            }
                        }
                    } else if fteid.v4 || fteid.v6 {
                        // only ipv4 for now
                        debug!("F-TEID is already allocated");
                        let fteid_pod = FteidPod::new(
                            fteid.ipv4_address.unwrap().to_bits(),
                            fteid.teid.value(),
                        );
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
                        error!("Exceeded maximum number of qfis in a PDI");
                        break;
                    }
                }

                for sdf in received_pdr.pdi.sdf_filters {
                    // TODO: parse sdf filter
                    debug!("SDF flow description in PDR: {}", sdf.flow_description);
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
                    (None, None) => {
                        debug!("Neither F-TEID nor UE IP was allocated");
                        CreatedPdr::new(pdr_id)
                    }
                };
                created_pdrs.push(created_pdr.to_ie());

                if pdr_info.pdi().pdi_mask().contains(PdiMask::UE_IPV4) {
                    session.insert_dl_pdr(pdr_info.pdr_id(), pdr_info);
                } else {
                    session.insert_ul_pdr(pdr_info.pdr_id(), pdr_info);
                }
            }
            Err(_) => {
                bail!("Error extracting PDR info");
            }
        }
    }

    Ok(created_pdrs)
}

pub async fn remove_rules(
    ctx: &PfcpContext,
    req: &SessionModificationRequest,
    session: &mut PfcpSession,
) -> anyhow::Result<()> {
    Ok(())
}
