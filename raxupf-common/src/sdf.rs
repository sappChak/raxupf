use core::net::IpAddr;

#[repr(C)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct SdfFilterPod {
    pub protocol: u8,
    pub src_ip: IpPod,
    pub dst_ip: IpPod,
    pub src_port_range: PortRange,
    pub dst_port_range: PortRange,
    pub allocated: bool,
}

#[repr(C)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct IpPod {
    version: u8,
    ip: u128,
    mask: u128,
}

impl IpPod {
    pub fn is_v4(&self) -> bool {
        self.version == 4
    }

    pub fn is_v6(&self) -> bool {
        self.version == 6
    }

    pub fn ip(&self) -> u128 {
        self.ip
    }

    pub fn mask(&self) -> u128 {
        self.mask
    }

    pub fn set_v4(&mut self, ip: u32, mask: u32) {
        self.version = 4;
        self.ip = ip as u128;
        self.mask = mask as u128;
    }

    pub fn set_v6(&mut self, ip: u128, mask: u128) {
        self.version = 6;
        self.ip = ip;
        self.mask = mask;
    }
}

#[repr(C)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl SdfFilterPod {
    #[inline(always)]
    pub fn matches(
        &self,
        src_ip: &IpAddr,
        dst_ip: &IpAddr,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        match (src_ip, dst_ip) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                let src_ip = u32::from(*src_ip) as u128;
                let dst_ip = u32::from(*dst_ip) as u128;
                (self.src_ip.is_v4() && (src_ip & self.src_ip.mask()) == self.src_ip.ip())
                    && (self.dst_ip.is_v4() && (dst_ip & self.dst_ip.mask()) == self.dst_ip.ip())
                    && self.protocol == protocol
                    && src_port >= self.src_port_range.start()
                    && src_port <= self.src_port_range.end()
                    && dst_port >= self.dst_port_range.start()
                    && dst_port <= self.dst_port_range.end()
            }
            _ => false,
        }
    }

    pub fn is_allocated(&self) -> bool {
        self.allocated
    }

    pub fn set_allocated(&mut self, allocated: bool) {
        self.allocated = allocated;
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    pub fn set_protocol(&mut self, protocol: u8) {
        self.protocol = protocol;
    }

    pub fn src_port_range(&self) -> &PortRange {
        &self.src_port_range
    }

    pub fn set_src_port_range(&mut self, src_port_range: PortRange) {
        self.src_port_range = src_port_range;
    }

    pub fn dst_port_range(&self) -> &PortRange {
        &self.dst_port_range
    }

    pub fn set_dst_port_range(&mut self, dst_port_range: PortRange) {
        self.dst_port_range = dst_port_range;
    }
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }

    pub fn start(&self) -> u16 {
        self.start
    }

    pub fn set_start(&mut self, start: u16) {
        self.start = start;
    }

    pub fn end(&self) -> u16 {
        self.end
    }

    pub fn set_end(&mut self, end: u16) {
        self.end = end;
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SdfFilterPod {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IpPod {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PortRange {}
