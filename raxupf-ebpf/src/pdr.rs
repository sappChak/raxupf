use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

    let (src_ip, dst_ip, protocol, src_port, dst_port) = match packet_ctx.gtp() {
        Some(gtp) => {
            let (sp, dp) = match &gtp.ports {
                Some(ports) => (ports.src_port(), ports.dst_port()),
                None => (0, 0),
            };
            (
                gtp.ip.src_ip(),
                gtp.ip.dst_ip(),
                gtp.ip.proto().into(),
                sp,
                dp,
            )
        }
        None => {
            // uplink without an inner packet is impossible
            if swap {
                return false;
            }
            let ip = packet_ctx.ip();
            let (sp, dp) = match &packet_ctx.ports() {
                Some(ports) => (ports.src_port(), ports.dst_port()),
                None => (0, 0),
            };
            (ip.src_ip(), ip.dst_ip(), ip.proto().into(), sp, dp)
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

fn ue_ip_matches(pdi: &PdiPod, ue_ip: &IpAddr) -> bool {
    if !pdi.pdi_mask().contains(PdiMask::UE_IP) {
        return true;
    }
    match ue_ip {
        IpAddr::V4(ue_ipv4) => {
            if pdi.ue_ip_address().is_v4()
                && pdi.ue_ip_address().ipv4_address() != ue_ipv4.to_bits()
            {
                return false;
            }
        }
        IpAddr::V6(ue_ipv6) => {
            if pdi.ue_ip_address().is_v6()
                && pdi.ue_ip_address().ipv6_address() != ue_ipv6.to_bits()
            {
                return false;
            }
        }
    };
    true
}

fn pdi_matches(pdi: &PdiPod, packet_ctx: &PacketContext) -> bool {
    if let Some(gtp) = packet_ctx.gtp() {
        let ue_ip = match pdi.source_interface() {
            SourceInterface::Access => {
                gtp.ip.src_ip() // packet is coming from the gNB over N3
            }
            SourceInterface::Core => {
                gtp.ip.dst_ip() // packet is coming from the anchor UPF over N9
            }
            _ => return false,
        };

        if pdi.pdi_mask().contains(PdiMask::F_TEID) && pdi.fteid() != gtp.gtpu.local_fteid {
            return false;
        }

        if !ue_ip_matches(pdi, ue_ip) {
            return false;
        }
    } else {
        // no inner packet -> it's N6, which can only match Core-side PDRs
        if !matches!(pdi.source_interface(), SourceInterface::Core) {
            return false;
        }
        if !ue_ip_matches(pdi, packet_ctx.dst_ip()) {
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

        let tunnelled = packet_ctx.gtp().is_some();
        let ohr_gtpu = pdr.ohr().contains(
            OuterHeaderRemovalFlags::GTPU_UDP_IPV4 | OuterHeaderRemovalFlags::GTPU_UDP_IPV6,
        );
        let ohc_gtpu = far
            .ohc()
            .contains(OhcFlags::GTPU_UDP_IPV4 | OhcFlags::GTPU_UDP_IPV6);

        // TODO: check whether FAR destination interface matches these decisions
        let (action, remote_ip) = match (tunnelled, ohr_gtpu, ohc_gtpu) {
            (true, true, true) => {
                let remote_ip = if pdr.ohr().contains(OuterHeaderRemovalFlags::GTPU_UDP_IPV4) {
                    IpAddr::V4(Ipv4Addr::from_bits(far.remote_ipv4()))
                } else {
                    IpAddr::V6(Ipv6Addr::from_bits(far.remote_ipv6()))
                };
                (PdrAction::Forward, remote_ip)
            }
            (true, true, false) => (PdrAction::Remove, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            (false, false, true) => {
                let remote_ip = if pdr.ohr().contains(OuterHeaderRemovalFlags::GTPU_UDP_IPV4) {
                    IpAddr::V4(Ipv4Addr::from_bits(far.remote_ipv4()))
                } else {
                    IpAddr::V6(Ipv6Addr::from_bits(far.remote_ipv6()))
                };
                (PdrAction::Create, remote_ip)
            }
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

        let parsed_pdr = ParsedPdr::new(far.teid(), qfi, far.dscp(), remote_ip, action);
        return Ok(parsed_pdr);
    }

    Err(xdp_action::XDP_DROP) // no PDR -> drop the packet
}
