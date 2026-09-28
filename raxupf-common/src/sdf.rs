#[repr(C)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct SdfFilterPod {
    protocol: u8,
    src_ip: u32,
    src_ip_mask: u32,
    dst_ip: u32,
    dst_ip_mask: u32,
    src_port_range: PortRange,
    dst_port_range: PortRange,
    allocated: bool,
}

#[repr(C)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl SdfFilterPod {
    pub fn matches(
        &self,
        src_ip: u32,
        dst_ip: u32,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        if src_ip & self.src_ip_mask != self.src_ip
            || dst_ip & self.dst_ip_mask != self.dst_ip
            || protocol != self.protocol
            || src_port > self.src_port_range().end()
            || src_port < self.src_port_range().start()
            || dst_port > self.dst_port_range().end()
            || dst_port < self.dst_port_range().start()
        {
            return false;
        }
        true
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

    pub fn src_ip(&self) -> u32 {
        self.src_ip
    }

    pub fn set_src_ip(&mut self, src_addr: u32) {
        self.src_ip = src_addr;
    }

    pub fn set_src_ip_mask(&mut self, src_ip_prefix: u32) {
        self.src_ip_mask = prefix_to_mask(src_ip_prefix);
    }

    pub fn dst_ip(&self) -> u32 {
        self.dst_ip
    }

    pub fn set_dst_ip(&mut self, dst_addr: u32) {
        self.dst_ip = dst_addr;
    }

    pub fn set_dst_ip_mask(&mut self, dst_ip_prefix: u32) {
        self.dst_ip_mask = prefix_to_mask(dst_ip_prefix);
    }

    pub fn src_port_range(&self) -> PortRange {
        self.src_port_range
    }

    pub fn set_src_port_range(&mut self, src_port_range: PortRange) {
        self.src_port_range = src_port_range;
    }

    pub fn dst_port_range(&self) -> PortRange {
        self.dst_port_range
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

fn prefix_to_mask(prefix: u32) -> u32 {
    if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SdfFilterPod {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PortRange {}
