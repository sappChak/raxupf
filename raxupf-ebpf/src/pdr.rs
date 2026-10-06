use core::net::Ipv4Addr;

use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::{debug, warn};
use raxupf_common::{
    PDR_MAP_SIZE,
    far::{FarAction, OhcFlags},
    pdi::{PdiMask, PdiPod, SourceInterface},
    pdr::{OuterHeaderRemovalFlags, PdrInfo},
};

use crate::{
    maps::{FAR_MAP, QER_MAP, URR_MAP},
    parser::{PacketContext, ParsedPdr, PdrAction},
};

fn sdf_matches(pdi: &PdiPod, packet_ctx: &PacketContext) -> bool {
    if !pdi.pdi_mask().contains(PdiMask::SDF_FILTER) {
        return true; // no SDF -> matches
    }

    // SDFs are in DL form, so for uplink (Access) swap src and dst
    let swap = match pdi.source_interface() {
        SourceInterface::Access => true,
        SourceInterface::Core => false,
        _ => return false,
    };

    let (src_ip, dst_ip, protocol, src_port, dst_port) = match packet_ctx.inner() {
        Some(inner) => {
            let (sp, dp) = match &inner.ports {
                Some(ports) => (ports.src_port(), ports.dst_port()),
                None => (0, 0),
            };
            (
                inner.ipv4.src_ipv4().to_bits(),
                inner.ipv4.dst_ipv4().to_bits(),
                inner.ipv4.protocol().into(),
                sp,
                dp,
            )
        }
        None => {
            // uplink without an inner packet is impossible
            if swap {
                return false;
            }
            let ip = packet_ctx.ipv4();
            let (sp, dp) = match &packet_ctx.ports() {
                Some(ports) => (ports.src_port(), ports.dst_port()),
                None => (0, 0),
            };
            (
                ip.src_ipv4().to_bits(),
                ip.dst_ipv4().to_bits(),
                ip.protocol().into(),
                sp,
                dp,
            )
        }
    };

    for sdf in pdi.sdfs().iter() {
        if !sdf.is_allocated() {
            break;
        }
        let hit = if swap {
            sdf.matches(dst_ip, src_ip, protocol, dst_port, src_port)
        } else {
            sdf.matches(src_ip, dst_ip, protocol, src_port, dst_port)
        };
        if hit {
            return true;
        }
    }
    false
}

fn pdi_matches(pdi: &PdiPod, packet_ctx: &PacketContext) -> bool {
    if let Some(inner) = packet_ctx.inner() {
        let ue_ip = match pdi.source_interface() {
            SourceInterface::Access => {
                inner.ipv4.src_ipv4().to_bits() // packet is coming from the gNB over N3
            }
            SourceInterface::Core => {
                inner.ipv4.dst_ipv4().to_bits() // packet is coming from the anchor UPF over N9
            }
            _ => return false,
        };

        if (pdi.pdi_mask().contains(PdiMask::F_TEID) && pdi.fteid() != inner.gtpu.local_fteid)
            || (pdi.pdi_mask().contains(PdiMask::UE_IP)
                && pdi.ue_ip_address().ipv4_address() != ue_ip)
        {
            return false;
        }
    } else {
        // no inner packet -> it's N6, which can only match Core-side PDRs
        if !matches!(pdi.source_interface(), SourceInterface::Core) {
            return false;
        }
        let ue_ip = packet_ctx.dst_ipv4().to_bits();
        if pdi.pdi_mask().contains(PdiMask::UE_IP) && pdi.ue_ip_address().ipv4_address() != ue_ip {
            return false;
        }
    };

    sdf_matches(pdi, packet_ctx)
}

#[inline(always)]
fn is_uplink(pdi: &PdiPod) -> bool {
    matches!(pdi.source_interface(), SourceInterface::Access)
}

#[inline(always)]
pub fn process_pdrs(
    ctx: &XdpContext,
    packet_ctx: &PacketContext,
    pdrs: &[PdrInfo; PDR_MAP_SIZE],
) -> Result<ParsedPdr, u32> {
    for pdr in pdrs.iter() {
        if !pdr.is_allocated() {
            continue;
        }

        let pdi = pdr.pdi();
        if !pdi_matches(&pdi, packet_ctx) {
            continue; // iterate over all PDRs to see whether at least one matches
        }
        let is_uplink = is_uplink(&pdi);

        let far = match unsafe { FAR_MAP.get(pdr.far_id()) } {
            Some(far) => {
                if far.action() == FarAction::FORW {
                    far
                } else {
                    warn!(ctx, "unsupported FAR action, dropping");
                    return Err(xdp_action::XDP_DROP);
                }
            }
            None => {
                debug!(ctx, "PDR points to non-existing FAR");
                return Err(xdp_action::XDP_DROP);
            }
        };

        let tunnelled = packet_ctx.inner().is_some();
        let ohr_gtpu = pdr.ohr().contains(OuterHeaderRemovalFlags::GTPU_UDP_IPV4);
        let ohc_gtpu = far.ohc().contains(OhcFlags::GTPU_UDP_IPV4);

        // TODO: check whether FAR destination interface matches these decisions
        let action = match (tunnelled, ohr_gtpu, ohc_gtpu) {
            (true, true, true) => PdrAction::Forward,
            (true, true, false) => PdrAction::Remove,
            (false, false, true) => PdrAction::Create,
            _ => {
                debug!(
                    ctx,
                    "PDR/FAR outer header handling doesn't fit the packet, dropping"
                );
                return Err(xdp_action::XDP_DROP);
            }
        };

        let mut qfi: u8 = 0;
        let mut allocated_qfi = false;
        for qer_id in pdr.qer_ids() {
            if let Some(qer) = unsafe { QER_MAP.get(qer_id) } {
                if qer.is_allocated() {
                    // TODO: enforce policies, implement rate limiting
                    if qer.is_closed(is_uplink) {
                        debug!(ctx, "QER is closed, dropping");
                        return Err(xdp_action::XDP_DROP);
                    }
                    if qer.has_qfi() {
                        qfi = qer.qfi();
                        allocated_qfi = true;
                    }
                } else {
                    break;
                }
            }
        }
        // only encapsulation writes a QFI into the packet
        if matches!(action, PdrAction::Create) && !allocated_qfi {
            debug!(ctx, "no QER with allocated QFI found, dropping");
            return Err(xdp_action::XDP_DROP);
        }

        for urr_id in pdr.urr_ids() {
            if let Some(urr) = unsafe { URR_MAP.get(urr_id) } {
                if urr.is_allocated() {
                    // TODO: implement it
                } else {
                    break;
                }
            }
        }

        return Ok(ParsedPdr::new(
            far.teid(),
            qfi,
            far.dscp(),
            Ipv4Addr::from(far.remote_ipv4()),
            action,
        ));
    }

    Err(xdp_action::XDP_DROP) // no PDR -> drop the packet
}
