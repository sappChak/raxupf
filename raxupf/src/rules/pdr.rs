use log::{debug, error};
use raxupf_common::{
    MAX_QFI_NUM,
    pdi::{PdiMask, PdiPod},
    pdr::PdrInfo,
};
use rs_pfcp::ie::{
    create_pdr::CreatePdr, created_pdr::CreatedPdr, source_interface::SourceInterfaceValue,
    update_pdr::UpdatePdr,
};

use crate::{
    iprule_parser::parse_sdf_filter,
    pfcp::PfcpContext,
    rules::helpers::{fteid_pod_to_ie, handle_fteid, handle_ue_ips, ueip_pod_to_ie},
    session::PfcpSession,
};

pub async fn create_pdr_rule(
    received_pdr: &CreatePdr,
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

    if let Some(fteid_pod) = handle_fteid(&received_pdr.pdi, ctx, &mut pdi_pod).await? {
        session.set_teid(fteid_pod.teid());
    };

    if let Some(ue_ip_pod) = handle_ue_ips(&received_pdr.pdi, ctx, &mut pdi_pod).await? {
        if ue_ip_pod.is_v4() {
            session.set_ue_ipv4(ue_ip_pod.ipv4_address().into());
        }
        if ue_ip_pod.is_v6() {
            session.set_ue_ipv6(ue_ip_pod.ipv6_address().into());
        }
    }

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
    let pdi_pod = pdr_info.pdi();
    let created_pdr = match (
        pdi_pod.pdi_mask().contains(PdiMask::F_TEID),
        pdi_pod.pdi_mask().contains(PdiMask::UE_IP),
    ) {
        (true, true) => {
            let fteid = fteid_pod_to_ie(&pdi_pod.fteid());
            let ue_ip = ueip_pod_to_ie(&pdi_pod.ue_ip_address());
            CreatedPdr::new(pdr_id).f_teid(fteid).ue_ip_address(ue_ip)
        }
        (true, false) => {
            let fteid = fteid_pod_to_ie(&pdi_pod.fteid());
            CreatedPdr::new(pdr_id).f_teid(fteid)
        }
        (false, true) => {
            let ue_ip = ueip_pod_to_ie(&pdi_pod.ue_ip_address());
            CreatedPdr::new(pdr_id).ue_ip_address(ue_ip)
        }
        (false, false) => CreatedPdr::new(pdr_id),
    };

    if pdr_info.pdi().pdi_mask().contains(PdiMask::UE_IP) {
        session.insert_dl_pdr(pdr_info.pdr_id(), pdr_info)?;
    } else {
        session.insert_ul_pdr(pdr_info.pdr_id(), pdr_info)?;
    }

    Ok(created_pdr)
}

pub async fn update_pdr_rule(
    update_pdr: UpdatePdr,
    ctx: &PfcpContext,
    session: &mut PfcpSession,
) -> anyhow::Result<()> {
    debug!("Incoming PDR update: {:?}", update_pdr);
    let pdr_id = update_pdr.pdr_id.value;

    if let Some(pdr_info) = session.ul_pdrs.get_mut(&pdr_id) {
        if let Some(precedence) = update_pdr.precedence {
            pdr_info.set_precedence(precedence.value);
        }

        if let Some(ohr) = update_pdr.outer_header_removal {
            pdr_info.set_ohr(ohr.description);
        }

        if let Some(pdi) = update_pdr.pdi {
            let mut pdi_pod = pdr_info.pdi();

            let _ = handle_fteid(&pdi, ctx, &mut pdi_pod).await;

            let _ = handle_ue_ips(&pdi, ctx, &mut pdi_pod).await;

            for (idx, qfi) in pdi.qfis.iter().enumerate() {
                if idx < MAX_QFI_NUM {
                    pdi_pod.set_qfi(idx, qfi.value());
                } else {
                    error!("Exceeded maximum number of qfis in a PDI");
                    break;
                }
            }

            for (idx, sdf) in pdi.sdf_filters.iter().enumerate() {
                let mut sdf_pod = parse_sdf_filter(sdf)?;
                sdf_pod.set_allocated(true);
                pdi_pod.set_sdf(idx, sdf_pod);
            }

            pdr_info.set_pdi(pdi_pod);
        }

        if let Some(far_id) = update_pdr.far_id {
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

pub fn remove_pdr_rule(pdr_id: u16) {}
