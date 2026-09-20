use core::net::Ipv4Addr;

use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::warn;
use raxupf_common::{
    far::{FarAction, OhcFlags},
    pdi::{PdiMask, PdiPod, SourceInterface},
    pdr::{OuterHeaderRemovalFlags, PdrInfo},
};

use crate::{
    maps::{FAR_MAP, QER_MAP, URR_MAP},
    parser::PacketContext,
};

pub enum PdrAction {
    Create,
    Remove,
    Forward,
}

pub struct ParsedPdr {
    pub teid: u32,
    pub qfi: u8,
    pub dscp: u8,
    pub remote_ipv4: Ipv4Addr,
    pub action: PdrAction,
}

#[inline(always)]
fn sdf_matches(pdi: &PdiPod, pkt: &PacketContext) -> bool {
    if pdi.pdi_mask().contains(PdiMask::SDF_FILTER) {
        for sdf in pdi.sdfs() {
            if sdf.is_allocated() {
                match pdi.source_interface() {
                    SourceInterface::Access => {
                        // todo!()
                    }
                    SourceInterface::Core => {
                        // todo!()
                    }
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
fn pdi_matches(pdi: &PdiPod, pkt: &PacketContext) -> bool {
    if let Some(inner) = pkt.inner() {
        let ue_ip = match pdi.source_interface() {
            SourceInterface::Access => {
                // packet is coming from the gNB over N3
                inner.ip.src_ipv4().to_bits()
            }
            SourceInterface::Core => {
                // packet is coming from the anchor UPF over N9
                inner.ip.dst_ipv4().to_bits()
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
        // no inner packet -> it's N6
        let ue_ip = pkt.dst_ipv4().to_bits();
        if pdi.pdi_mask().contains(PdiMask::UE_IP) && pdi.ue_ip_address().ipv4_address() != ue_ip {
            return false;
        }
    };

    sdf_matches(pdi, pkt)
}

pub fn process_pdrs(
    ctx: &XdpContext,
    packet_ctx: &PacketContext,
    pdrs: &[PdrInfo],
) -> Result<ParsedPdr, u32> {
    for pdr in pdrs {
        if pdr.is_allocated() {
            let pdi = pdr.pdi();

            if !pdi_matches(&pdi, packet_ctx) {
                // iterate over all PDRs to see whether at least one matches
                continue;
            }

            let far_id = pdr.far_id();
            let ohr = pdr.ohr();
            let far = match unsafe { FAR_MAP.get(far_id) } {
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
                    if qer.is_closed() {
                        return Err(xdp_action::XDP_DROP);
                    }
                    if qer.has_qfi() {
                        qfi = qer.qfi();
                        allocated_qfi = true;
                    }
                    // TODO: enforce policies, implement rate limiting
                }
            }
            if !allocated_qfi {
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
