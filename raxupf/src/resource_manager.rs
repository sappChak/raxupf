use std::{
    collections::{HashMap, hash_map::Entry},
    net::{Ipv4Addr, Ipv6Addr},
};

use log::debug;

pub struct ResourceManager {
    teids: HashMap<u8, u32>,
}

impl ResourceManager {
    pub fn new() -> Self {
        Self {
            teids: HashMap::new(),
        }
    }

    pub fn allocate_local_fteid(&mut self) -> anyhow::Result<rs_pfcp::Teid> {
        todo!()
    }

    pub fn allocate_local_fteid_chid(&mut self, choose_id: u8) -> anyhow::Result<rs_pfcp::Teid> {
        debug!("allocating F-TEID");
        match self.teids.entry(choose_id) {
            Entry::Occupied(occupied_entry) => todo!(),
            Entry::Vacant(vacant_entry) => todo!(),
        }
    }

    pub fn allocate_ue_ipv4(&mut self) -> anyhow::Result<Ipv4Addr> {
        debug!("allocating UE IPv4...");
        todo!()
    }

    pub fn allocate_ue_ipv6(&mut self) -> anyhow::Result<Ipv6Addr> {
        debug!("allocating UE IPv6...");
        todo!()
    }
}
