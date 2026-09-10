use std::collections::{HashMap, hash_map::Entry};

use log::debug;
use rs_pfcp::{
    error::PfcpError,
    ie::{f_teid::Fteid, ue_ip_address::UeIpAddress},
};

pub struct ResourceManager {
    teids: HashMap<u8, u32>,
}

impl ResourceManager {
    pub fn new() -> Self {
        Self {
            teids: HashMap::new(),
        }
    }

    pub fn allocate_local_fteid(&mut self) -> Result<Fteid, PfcpError> {
        todo!()
    }

    pub fn allocate_local_fteid_chid(&mut self, choose_id: u8) -> Result<Fteid, PfcpError> {
        debug!("allocating F-TEID");
        match self.teids.entry(choose_id) {
            Entry::Occupied(occupied_entry) => todo!(),
            Entry::Vacant(vacant_entry) => todo!(),
        }
    }

    pub fn allocate_ue_ip(&mut self) -> Result<UeIpAddress, PfcpError> {
        debug!("allocating UE IP...");
        todo!()
    }
}
