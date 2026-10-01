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
    parser::PacketContext,
};

#[derive(Debug)]
pub enum PdrAction {
    Create,
    Remove,
    Forward,
}

#[derive(Debug)]
pub struct ParsedPdr {
    pub teid: u32,
    pub qfi: u8,
    pub dscp: u8,
    pub remote_ipv4: Ipv4Addr,
    pub action: PdrAction,
}

fn sdf_matches(pdi: &PdiPod, packet_ctx: &PacketContext) -> bool {
    if pdi.pdi_mask().contains(PdiMask::SDF_FILTER) {
        for sdf in pdi.sdfs() {
            if sdf.is_allocated() {
                match pdi.source_interface() {
                    SourceInterface::Access => {
                        if let Some(inner) = packet_ctx.inner() {
                            let src_ip = inner.ipv4.src_ipv4().to_bits();
                            let dst_ip = inner.ipv4.dst_ipv4().to_bits();
                            let protocol = inner.ipv4.protocol().into();
                            let (src_port, dst_port) = match &inner.ports {
                                Some(ports) => (ports.src_port(), ports.dst_port()),
                                None => (0, 0),
                            };
                            // SDF is always in DL form, so swap dest and src
                            if sdf.matches(dst_ip, src_ip, protocol, dst_port, src_port) {
                                return true;
                            }
                        } else {
                            // Ain't possible
                            break;
                        }
                    }
                    SourceInterface::Core => match packet_ctx.inner() {
                        Some(inner) => {
                            let src_ip = inner.ipv4.src_ipv4().to_bits();
                            let dst_ip = inner.ipv4.dst_ipv4().to_bits();
                            let protocol = inner.ipv4.protocol().into();
                            let (src_port, dst_port) = match &inner.ports {
                                Some(ports) => (ports.src_port(), ports.dst_port()),
                                None => (0, 0),
                            };
                            if sdf.matches(src_ip, dst_ip, protocol, src_port, dst_port) {
                                return true;
                            }
                        }
                        None => {
                            let src_ip = packet_ctx.ipv4().src_ipv4().to_bits();
                            let dst_ip = packet_ctx.ipv4().dst_ipv4().to_bits();
                            let protocol = packet_ctx.ipv4().protocol().into();
                            let (src_port, dst_port) = match &packet_ctx.ports() {
                                Some(ports) => (ports.src_port(), ports.dst_port()),
                                None => (0, 0),
                            };
                            if sdf.matches(src_ip, dst_ip, protocol, src_port, dst_port) {
                                return true;
                            }
                        }
                    },
                    _ => break,
                }
            } else {
                break;
            }
        }
    }
    false
}

#[inline(always)]
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
        true
    } else {
        // no inner packet -> it's N6
        let ue_ip = packet_ctx.dst_ipv4().to_bits();
        if pdi.pdi_mask().contains(PdiMask::UE_IP) && pdi.ue_ip_address().ipv4_address() != ue_ip {
            return false;
        }
        false
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
    for pdr in pdrs {
        if pdr.is_allocated() {
            if !pdi_matches(&pdr.pdi(), packet_ctx) {
                continue; // iterate over all PDRs to see whether at least one matches
            }
            let is_uplink = is_uplink(&pdr.pdi());

            let far = match unsafe { FAR_MAP.get(pdr.far_id()) } {
                Some(far) => {
                    let action = far.action();
                    if action == FarAction::FORW {
                        far
                    } else {
                        warn!(ctx, "unsupported FAR action, dropping...");
                        return Err(xdp_action::XDP_DROP);
                    }
                }
                None => return Err(xdp_action::XDP_DROP),
            };

            let mut qfi: u8 = 0;
            let mut allocated_qfi = false;
            for qer_id in pdr.qer_ids() {
                if let Some(qer) = unsafe { QER_MAP.get(qer_id) } {
                    // TODO: enforce policies, implement rate limiting
                    if qer.is_closed(is_uplink) {
                        debug!(ctx, "QER is closed, dropping...");
                        return Err(xdp_action::XDP_DROP);
                    }
                    if qer.has_qfi() {
                        qfi = qer.qfi();
                        allocated_qfi = true;
                    }
                }
            }
            if !allocated_qfi {
                debug!(ctx, "no QER with allocated QFI found, dropping...");
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

            // TODO: check whether FAR destination interface matches these decisions
            let ohr = pdr.ohr();
            let action: PdrAction = if ohr.contains(OuterHeaderRemovalFlags::GTPU_UDP_IPV4)
                && far.ohc().contains(OhcFlags::GTPU_UDP_IPV4)
            {
                // this is N9
                PdrAction::Forward
            } else if far.ohc().contains(OhcFlags::GTPU_UDP_IPV4) {
                // this is N6
                PdrAction::Create
            } else {
                // this is N3
                PdrAction::Remove
            };

            return Ok(ParsedPdr {
                teid: far.teid(),
                qfi,
                dscp: far.dscp(),
                remote_ipv4: Ipv4Addr::from(far.remote_ipv4()),
                action,
            });
        }
    }

    Err(xdp_action::XDP_DROP) // no PDR -> drop the packet
}
