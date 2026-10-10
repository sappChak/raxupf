pub struct PfcpAssociation {
    lnode_id: String,
    laddr: std::net::IpAddr,
    lseid: u64,
}

impl PfcpAssociation {
    pub fn new(lnode_id: String, laddr: std::net::IpAddr) -> Self {
        Self {
            lnode_id,
            laddr,
            lseid: 1,
        }
    }

    pub fn lnode_id(&self) -> &str {
        &self.lnode_id
    }

    pub fn laddr(&self) -> std::net::IpAddr {
        self.laddr
    }

    pub fn allocate_up_seid(&mut self) -> u64 {
        self.lseid += 1;
        self.lseid
    }
}
