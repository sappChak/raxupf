use core::net::Ipv4Addr;

use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::{
    GTP_PROTOCOL_TYPE, GTP_VERSION, MAX_EXT_HDRS,
    gtpu::{GtpuExtensionType, GtpuHdr, GtpuMessageType, GtpuOptFields},
    helpers::{ptr_at, ptr_at_mut},
    pdu::{DLPduSession, GtpuDLPduExtensionHdr, ULPduSession},
};

pub const GTPU_EXT_LEN: usize = GtpuOptFields::LEN + GtpuDLPduExtensionHdr::LEN;
pub const GTPU_HDR_LEN: usize = GtpuHdr::LEN + GTPU_EXT_LEN;
pub const OUTER_HDRS_LEN_SUM: usize = Ipv4Hdr::LEN + UdpHdr::LEN + GTPU_HDR_LEN;

use aya_log_ebpf::{error, info};
use raxupf_common::fteid::FteidPod;

pub struct ParsedIpv4 {
    src_ipv4: Ipv4Addr,
    dst_ipv4: Ipv4Addr,
    tot_len: usize,
}

impl ParsedIpv4 {
    pub fn new(src_ipv4: Ipv4Addr, dst_ipv4: Ipv4Addr, tot_len: usize) -> Self {
        Self {
            src_ipv4,
            dst_ipv4,
            tot_len,
        }
    }

    pub fn src_ipv4(&self) -> Ipv4Addr {
        self.src_ipv4
    }

    pub fn dst_ipv4(&self) -> Ipv4Addr {
        self.dst_ipv4
    }
}

#[derive(Default)]
pub struct ParsedPorts {
    src: u16,
    dst: u16,
}

impl ParsedPorts {
    fn new(src: u16, dst: u16) -> Self {
        Self { src, dst }
    }
}

pub struct ParsedInner {
    pub ip: ParsedIpv4,
    pub ports: ParsedPorts,
    pub gtpu: ParsedGtpu,
    pub psc: ParsedPsc,
}

pub struct ParsedGtpu {
    pub local_fteid: FteidPod,
    pub message_type: GtpuMessageType,
    pub has_flags: bool,
    pub has_extension_header: bool,
}

pub struct PacketContext {
    ipv4: ParsedIpv4,
    upf_ipv4: Ipv4Addr,
    ports: ParsedPorts,
    inner: Option<ParsedInner>,
}

impl PacketContext {
    pub fn new(ipv4: ParsedIpv4, upf_ipv4: Ipv4Addr) -> Self {
        Self {
            ipv4,
            upf_ipv4,
            ports: ParsedPorts::default(),
            inner: None,
        }
    }

    pub fn set_ports(&mut self, src: u16, dst: u16) {
        self.ports = ParsedPorts { src, dst }
    }

    pub fn upf_ipv4(&self) -> Ipv4Addr {
        self.upf_ipv4
    }

    pub fn src_port(&self) -> u16 {
        self.ports.src
    }

    pub fn dst_port(&self) -> u16 {
        self.ports.dst
    }

    pub fn src_ipv4(&self) -> Ipv4Addr {
        self.ipv4.src_ipv4
    }

    pub fn dst_ipv4(&self) -> Ipv4Addr {
        self.ipv4.dst_ipv4
    }

    pub fn inner(&self) -> Option<&ParsedInner> {
        self.inner.as_ref()
    }

    pub fn set_inner(&mut self, inner: ParsedInner) {
        self.inner = Some(inner)
    }

    pub fn parse_inner(&mut self, ctx: &XdpContext) -> Result<(), u32> {
        // TODO: fix horrible return types and their handling
        let parsed_gtpu = parse_gtpu_header(ctx, self.upf_ipv4)?;

        let parsed_psc = match parse_pdu_session_container(ctx) {
            Ok(psc) => psc,
            Err(_) => return Err(xdp_action::XDP_ABORTED),
        };

        let (parsed_ipv4, parsed_ports) = match self.parse_inner_headers(ctx) {
            Ok(ok) => ok,
            Err(_) => return Err(xdp_action::XDP_ABORTED),
        };

        let inner = ParsedInner {
            ip: parsed_ipv4,
            ports: parsed_ports,
            gtpu: parsed_gtpu,
            psc: parsed_psc,
        };

        self.set_inner(inner);

        Ok(())
    }

    fn parse_inner_headers(&mut self, ctx: &XdpContext) -> Result<(ParsedIpv4, ParsedPorts), ()> {
        let offset = EthHdr::LEN + OUTER_HDRS_LEN_SUM;
        let inner_ipv4: &Ipv4Hdr = match ptr_at(ctx, offset) {
            Ok(ptr) => unsafe { &*ptr },
            Err(_) => return Err(()),
        };
        let parsed_ipv4 = ParsedIpv4::new(
            inner_ipv4.src_addr(),
            inner_ipv4.src_addr(),
            inner_ipv4.tot_len() as usize,
        );

        let (src_port, dst_port) = match inner_ipv4.proto() {
            Ok(IpProto::Udp) => {
                let inner_udph: &UdpHdr = match ptr_at(ctx, offset + Ipv4Hdr::LEN) {
                    Ok(ptr) => unsafe { &*ptr },
                    Err(_) => return Err(()),
                };
                (inner_udph.src_port(), inner_udph.dst_port())
            }
            Ok(IpProto::Tcp) => {
                let inner_tcph: &TcpHdr = match ptr_at(ctx, offset + Ipv4Hdr::LEN) {
                    Ok(ptr) => unsafe { &*ptr },
                    Err(_) => return Err(()),
                };
                (
                    u16::from_be_bytes(inner_tcph.source),
                    u16::from_be_bytes(inner_tcph.dest),
                )
            }
            _ => {
                error!(ctx, "error parsing inner ipv4 protocol");
                return Err(());
            }
        };
        let parsed_port = ParsedPorts::new(src_port, dst_port);

        Ok((parsed_ipv4, parsed_port))
    }
}

pub struct ParsedPsc {
    ext_tot_len: usize,
    qfi: u8,
}

impl ParsedPsc {
    pub fn ext_tot_len(&self) -> usize {
        self.ext_tot_len
    }

    pub fn qfi(&self) -> u8 {
        self.qfi
    }
}

pub fn parse_pdu_session_container(ctx: &XdpContext) -> Result<ParsedPsc, ()> {
    let mut offset = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + GtpuHdr::LEN;
    let gtpu_opt: &GtpuOptFields = unsafe { &*ptr_at(ctx, offset)? };

    let seq_num = gtpu_opt.sequence_number();
    info!(&ctx, "seq number is: {}", seq_num);

    let npdu_num = gtpu_opt.npdu_number();
    info!(&ctx, "npdu number is: {}", npdu_num);

    let mut exth_type = gtpu_opt.next_extension_header_type();

    let (mut ext_tot_len, mut qfi) = (0, None);
    offset += GtpuOptFields::LEN;
    for _ in 0..MAX_EXT_HDRS {
        if let Ok(GtpuExtensionType::NoMoreExtensions) = exth_type {
            break;
        }

        let n: u8 = unsafe { *ptr_at(ctx, offset)? }; // the size of extension block in words
        let ext_hdr_length: usize = n as usize * 4;

        if ctx.data() + offset + ext_hdr_length > ctx.data_end() {
            return Err(());
        }

        ext_tot_len += ext_hdr_length;
        offset += 1; // ext hdr length field is 1 byte long
        match exth_type {
            Ok(GtpuExtensionType::PduSessionContainer) => {
                info!(&ctx, "next extension header is PDU Session Container");
                // TODO: use enum instead of magic numbers
                let pdu_type = unsafe { *ptr_at::<u8>(ctx, offset)? } >> 4; // PDU type field goes first

                match pdu_type {
                    0 => {
                        let dl_pdu: &DLPduSession = unsafe { &*ptr_at(ctx, offset)? };
                        qfi = Some(dl_pdu.qfi());
                        offset += DLPduSession::LEN;
                    }
                    1 => {
                        let ul_pdu: &ULPduSession = unsafe { &*ptr_at(ctx, offset)? };
                        qfi = Some(ul_pdu.qfi());
                        offset += ULPduSession::LEN;
                    }
                    _ => {
                        break;
                    }
                }
            }
            Ok(_) => {
                // TODO: handle other supported containers
            }
            Err(_) => {
                // TODO: handle comprehensive bits
            }
        }
        let next_ext_hdr_type = unsafe { *ptr_at::<u8>(ctx, offset)? };
        exth_type = GtpuExtensionType::try_from(next_ext_hdr_type);
    }

    let qfi = if let Some(qfi) = qfi {
        qfi
    } else {
        error!(ctx, "no qfi for some reason while parsing psc");
        return Err(());
    };

    Ok(ParsedPsc { ext_tot_len, qfi })
}

#[inline(always)]
pub fn parse_gtpu_header(ctx: &XdpContext, upf_ip: Ipv4Addr) -> Result<ParsedGtpu, u32> {
    let gtpuh: &GtpuHdr = match ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) {
        Ok(ptr) => unsafe { &*ptr },
        Err(_) => {
            error!(ctx, "error parsing gtpu header in a gtp-u packet");
            return Err(xdp_action::XDP_ABORTED);
        }
    };

    match (gtpuh.protocol_type(), gtpuh.version()) {
        (GTP_PROTOCOL_TYPE, GTP_VERSION) => {}
        _ => return Err(xdp_action::XDP_PASS), // everything not GTP-U is passed
    }

    let message_type = match gtpuh.message_type() {
        Ok(GtpuMessageType::GPdu) => GtpuMessageType::GPdu,
        Ok(GtpuMessageType::EchoRequest) => GtpuMessageType::EchoRequest,
        Ok(GtpuMessageType::EchoResponse) => GtpuMessageType::EchoRequest,
        Ok(GtpuMessageType::ErrorIndication) => GtpuMessageType::ErrorIndication,
        Ok(GtpuMessageType::EndMarker) => GtpuMessageType::EndMarker,
        Ok(GtpuMessageType::SupportedExtensionHeaders) => {
            GtpuMessageType::SupportedExtensionHeaders
        }
        Ok(GtpuMessageType::TunnelStatus) => GtpuMessageType::TunnelStatus,
        Err(_) => {
            return Err(xdp_action::XDP_DROP);
        }
    };

    Ok(ParsedGtpu {
        local_fteid: FteidPod::new(gtpuh.teid(), upf_ip.to_bits()),
        message_type,
        has_flags: gtpuh.has_flags(),
        has_extension_header: gtpuh.has_extension_header(),
    })
}
