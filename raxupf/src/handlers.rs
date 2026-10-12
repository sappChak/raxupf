use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::bail;
use log::{debug, error, warn};
use rs_pfcp::{
    error::PfcpError,
    ie::{
        Ie, cause::CauseValue, create_far::CreateFar, create_pdr::CreatePdr, create_qer::CreateQer,
        create_urr::CreateUrr, far_id::FarId, fseid::Fseid, node_id::NodeId, pdn_type::PdnType,
        pdr_id::PdrId, qer_id::QerId, recovery_time_stamp::RecoveryTimeStamp,
        update_far::UpdateFar, update_pdr::UpdatePdr, update_qer::UpdateQer, update_urr::UpdateUrr,
        urr_id::UrrId,
    },
    message::{
        AssociationSetupRequest, Message, SessionEstablishmentRequest, SessionModificationRequest,
        association_setup_response::AssociationSetupResponseBuilder,
        session_establishment_response::SessionEstablishmentResponseBuilder,
        session_modification_response::SessionModificationResponseBuilder,
    },
};

use crate::{
    association::PfcpAssociation,
    pfcp::PfcpContext,
    rules::{
        far::{create_far_rule, remove_far_rule, update_far_rule},
        pdr::{create_pdr_rule, remove_pdr_rule, update_pdr_rule},
        qer::{create_qer_rule, remove_qer_rule, update_qer_rule},
        urr::{create_urr_rule, remove_urr_rule, update_urr_rule},
    },
    session::PfcpSession,
};

pub async fn handle_association_setup_request(
    ctx: &PfcpContext,
    req: &AssociationSetupRequest,
    remote_addr: SocketAddr,
) -> anyhow::Result<()> {
    // message handling in accordance to 29.244, clause 6.2.6.2.2

    let rnode_id = match req.node_id.parse::<NodeId>() {
        Ok(node_id) => match node_id {
            NodeId::IPv4(ipv4_addr) => ipv4_addr.to_string(),
            NodeId::IPv6(ipv6_addr) => ipv6_addr.to_string(),
            NodeId::FQDN(fqdn) => fqdn,
        },
        Err(_) => {
            bail!("Error parsing remote node id");
        }
    };
    debug!("remote node id is: {}", rnode_id);

    let _recovery: std::time::SystemTime =
        match req.recovery_time_stamp.parse::<RecoveryTimeStamp>() {
            Ok(rec_ts) => rec_ts.timestamp,
            Err(_) => {
                bail!("Error parsing recovery timestamp");
            }
        };

    // shall store the Node ID of the CP function as the identifier of the PFCP association
    let association = PfcpAssociation::new(rnode_id.clone(), remote_addr.ip());
    let _ = ctx.insert_association(&rnode_id, association).await;

    let node_id = ctx.node_id();
    let node_id = if let Ok(ip_v4) = node_id.parse::<Ipv4Addr>() {
        NodeId::IPv4(ip_v4)
    } else if let Ok(ip_v6) = node_id.parse::<Ipv6Addr>() {
        NodeId::IPv6(ip_v6)
    } else {
        NodeId::new_fqdn(node_id)
    };

    // TODO: information of all supported optional features in the UP function
    let response = AssociationSetupResponseBuilder::new(req.sequence())
        .cause(CauseValue::RequestAccepted)
        .node_id_ie(node_id.to_ie())
        .recovery_time_stamp(ctx.recovery_ts())
        .build();

    ctx.send_response(&response.marshal(), remote_addr).await
}

pub async fn handle_session_establishment_request(
    ctx: &PfcpContext,
    req: &SessionEstablishmentRequest,
    cp_addr: SocketAddr,
) -> anyhow::Result<()> {
    let cp_seid = match req.fseid.parse::<Fseid>() {
        Ok(fs) => *fs.seid,
        Err(_) => bail!("session establishment request missing SEID"),
    };

    let cp_nodeid = match req.node_id.parse::<NodeId>() {
        Ok(node_id) => match node_id {
            NodeId::IPv4(ipv4_addr) => ipv4_addr.to_string(),
            NodeId::IPv6(ipv6_addr) => ipv6_addr.to_string(),
            NodeId::FQDN(fqdn) => fqdn,
        },
        Err(_) => {
            bail!("Error parsing remote node id");
        }
    };

    let up_seid: u64 = if let Some(up_seid) = ctx
        .with_association_mut(&cp_nodeid, |association| association.allocate_up_seid())
        .await
    {
        up_seid
    } else {
        warn!("session establishment request for non-existing association");
        let response = SessionEstablishmentResponseBuilder::new(
            0,
            req.sequence(),
            CauseValue::NoEstablishedPfcpAssociation,
        )
        .node_id(ctx.local_pfcp_addr().ip())
        .fseid_ie(Ie::new(rs_pfcp::ie::IeType::Fseid, vec![])); // Fseid should be None for rejection responses, PR to rs-pfcp
        return ctx.send_response(&response.marshal()?, cp_addr).await;
    };

    // let pdn_type: u8 = match req.pdn_type {
    //     Some(pdn_type) => match pdn_type.parse::<PdnType>() {
    //         Ok(pdn_type) => pdn_type.pdn_type.into(),
    //         Err(_) => bail!("error parsing pdn_type"),
    //     },
    //     None => {
    //         bail!("session establishment request missing PDN Type");
    //     }
    // };

    let mut session = PfcpSession::new(cp_nodeid, cp_seid);

    // TODO: implement rollback on failure
    debug!("Processing {} CreateFar IEs", req.create_fars.len());
    for (idx, create_far) in req.create_fars.iter().enumerate() {
        match create_far.parse::<CreateFar>() {
            Ok(received_far) => {
                create_far_rule(received_far, &mut session)?;
            }
            Err(_) => {
                bail!("Error extracting CreateFAR");
            }
        }
    }

    debug!("Processing {} CreateQer ies", req.create_qers.len());
    for (idx, create_qer) in req.create_qers.iter().enumerate() {
        match create_qer.parse::<CreateQer>() {
            Ok(received_qer) => {
                create_qer_rule(received_qer, &mut session)?;
            }
            Err(_) => {
                bail!("Error extracting CreateQER");
            }
        };
    }

    debug!("Processing {} CreateUrr ies", req.create_urrs.len());
    for (idx, create_urr) in req.create_urrs.iter().enumerate() {
        match create_urr.parse::<CreateUrr>() {
            Ok(received_urr) => {
                create_urr_rule(received_urr, &mut session)?;
            }
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
                let created_pdr = create_pdr_rule(&received_pdr, ctx, &mut session).await?;
                created_pdrs.push(created_pdr.to_ie());
            }
            Err(_) => {
                bail!("Error extracting PDR info");
            }
        }
    }

    let mut response_builder =
        SessionEstablishmentResponseBuilder::accepted(cp_seid, req.sequence())
            .node_id(ctx.local_pfcp_addr().ip())
            .fseid(up_seid, ctx.local_pfcp_addr().ip());

    // add all created pdrs to the response
    for created_pdr in created_pdrs {
        response_builder = response_builder.created_pdr(created_pdr);
    }

    let res = match response_builder.marshal() {
        Ok(r) => r,
        Err(PfcpError::MissingMandatoryIe { ie_type, .. }) => {
            error!("Missing mandatory ie {:?} - sending rejection", ie_type);
            SessionEstablishmentResponseBuilder::rejected(cp_seid, req.sequence())
                .node_id(ctx.local_pfcp_addr().ip())
                .marshal()?
        }
        Err(e) => {
            error!("Failed to build session establishment response: {e} - sending rejection");
            SessionEstablishmentResponseBuilder::rejected(cp_seid, req.sequence())
                .node_id(ctx.local_pfcp_addr().ip())
                .marshal()?
        }
    };

    debug!("Inserting NEW session with SEID: 0x{up_seid:016x}");
    ctx.compile_session(session.clone()).await?;
    ctx.insert_session(up_seid, session).await;

    ctx.send_response(&res, cp_addr).await
}

pub async fn handle_session_modification_request(
    ctx: &PfcpContext,
    req: &SessionModificationRequest,
    cp_addr: SocketAddr,
) -> anyhow::Result<()> {
    // SMF sends SEID that was previously allocated by UPF
    let up_seid = match req.seid() {
        Some(s) => *s,
        None => {
            bail!("Session establishment request missing SEID");
        }
    };

    // get a cloned version of a session, updated version'll be reinserted later
    let mut session: PfcpSession = match ctx.get_session(up_seid).await {
        Some(session) => session,
        None => {
            warn!(
                "session modification request for non-existing session up_seid: 0x{up_seid:016x}"
            );
            let rejection = SessionModificationResponseBuilder::new(up_seid, req.sequence())
                .cause(CauseValue::SessionContextNotFound);
            return ctx.send_response(&rejection.marshal(), cp_addr).await;
        }
    };

    if let Some(remove_fars) = &req.remove_fars {
        debug!("Processing {} RemoveFar IEs", remove_fars.len());
        for (idx, remove_far) in remove_fars.iter().enumerate() {
            match remove_far.parse::<FarId>() {
                Ok(received_far_id) => {
                    remove_far_rule(received_far_id.value);
                }
                Err(_) => bail!("error extracting far ID from RemoveFar IE"),
            }
        }
    }

    if let Some(remove_qers) = &req.remove_qers {
        debug!("Processing {} RemoveQER IEs", remove_qers.len());
        for (idx, remove_qer) in remove_qers.iter().enumerate() {
            match remove_qer.parse::<QerId>() {
                Ok(received_qer_id) => {
                    remove_qer_rule(received_qer_id.value);
                }
                Err(_) => bail!("error extracting qer ID from RemoveQER IE"),
            }
        }
    }

    if let Some(remove_urrs) = &req.remove_urrs {
        debug!("Processing {} RemoveURR IEs", remove_urrs.len());
        for (idx, remove_urr) in remove_urrs.iter().enumerate() {
            match remove_urr.parse::<UrrId>() {
                Ok(received_urr_id) => {
                    remove_urr_rule(received_urr_id.id);
                }
                Err(_) => bail!("error extracting urr ID from RemoveURR IE"),
            }
        }
    }

    if let Some(remove_pdrs) = &req.remove_pdrs {
        debug!("Processing {} RemovePDR IEs", remove_pdrs.len());
        for (idx, remove_pdr) in remove_pdrs.iter().enumerate() {
            match remove_pdr.parse::<PdrId>() {
                Ok(received_pdr_id) => {
                    remove_pdr_rule(received_pdr_id.value);
                }
                Err(_) => bail!("error extracting far ID from RemoveFar IE"),
            }
        }
    }

    // TODO: implement rollback on failure
    if let Some(create_fars) = &req.create_fars {
        debug!("Processing {} CreateFar IEs", create_fars.len());
        for (idx, create_far) in create_fars.iter().enumerate() {
            match create_far.parse::<CreateFar>() {
                Ok(received_far) => {
                    create_far_rule(received_far, &mut session)?;
                }
                Err(_) => {
                    bail!("Error extracting CreateFAR");
                }
            }
        }
    }

    if let Some(create_qers) = &req.create_qers {
        debug!("Processing {} CreateQer ies", create_qers.len());
        for (idx, create_qer) in create_qers.iter().enumerate() {
            match create_qer.parse::<CreateQer>() {
                Ok(received_qer) => {
                    create_qer_rule(received_qer, &mut session)?;
                }
                Err(_) => {
                    bail!("Error extracting CreateQER");
                }
            };
        }
    }

    if let Some(create_urrs) = &req.create_urrs {
        debug!("Processing {} CreateUrr ies", create_urrs.len());
        for (idx, create_urr) in create_urrs.iter().enumerate() {
            match create_urr.parse::<CreateUrr>() {
                Ok(received_urr) => {
                    create_urr_rule(received_urr, &mut session)?;
                }
                Err(_) => {
                    bail!("Error extracting CreateUrr");
                }
            };
        }
    }

    let mut created_pdrs: Vec<Ie> = Vec::new();
    if let Some(create_pdrs) = &req.create_pdrs {
        debug!("Processing {} CreatePdr ies", create_pdrs.len());
        for (idx, create_pdr_ie) in create_pdrs.iter().enumerate() {
            match create_pdr_ie.parse::<CreatePdr>() {
                Ok(received_pdr) => {
                    let created_pdr = create_pdr_rule(&received_pdr, ctx, &mut session).await?;
                    created_pdrs.push(created_pdr.to_ie());
                }
                Err(_) => {
                    bail!("Error extracting PDR info");
                }
            }
        }
    }

    if let Some(update_far) = &req.update_fars {
        debug!("Processing {} UpdateFar IEs", update_far.len());
        for (idx, update_far) in update_far.iter().enumerate() {
            match update_far.parse::<UpdateFar>() {
                Ok(received_far) => {
                    update_far_rule(received_far, &mut session);
                }
                Err(_) => {
                    bail!("Error extracting UpdateFAR");
                }
            }
        }
    }

    if let Some(update_qers) = &req.update_qers {
        debug!("Processing {} UpdateQer ies", update_qers.len());
        for (idx, update_qer) in update_qers.iter().enumerate() {
            match update_qer.parse::<UpdateQer>() {
                Ok(received_qer) => {
                    update_qer_rule(received_qer, &mut session);
                }
                Err(_) => {
                    bail!("Error extracting UpdateQER");
                }
            };
        }
    }

    if let Some(update_urrs) = &req.update_urrs {
        debug!("Processing {} UpdateUrr ies", update_urrs.len());
        for (idx, update_urr) in update_urrs.iter().enumerate() {
            match update_urr.parse::<UpdateUrr>() {
                Ok(received_urr) => {
                    update_urr_rule(received_urr, &mut session);
                }
                Err(_) => {
                    bail!("Error extracting UpdateUrr");
                }
            };
        }
    }

    if let Some(update_pdrs) = &req.update_pdrs {
        debug!("Processing {} UpdatePdr ies", update_pdrs.len());
        for (idx, update_pdr_ie) in update_pdrs.iter().enumerate() {
            match update_pdr_ie.parse::<UpdatePdr>() {
                Ok(received_pdr) => {
                    update_pdr_rule(received_pdr, ctx, &mut session).await?;
                }
                Err(_) => {
                    bail!("Error extracting PDR info");
                }
            }
        }
    }

    let res = SessionModificationResponseBuilder::accepted(session.cp_seid(), req.sequence())
        .created_pdrs(created_pdrs);

    debug!("Inserting UPDATED session with SEID: 0x{up_seid:016x}");
    ctx.compile_session(session.clone()).await?;
    ctx.insert_session(up_seid, session).await;

    ctx.send_response(&res.marshal(), cp_addr).await
}
