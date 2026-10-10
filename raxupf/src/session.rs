use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::bail;
use raxupf_common::{
    FAR_MAP_SIZE, PDR_MAP_SIZE, QER_MAP_SIZE, URR_MAP_SIZE, far::FarInfo, pdr::PdrInfo,
    qer::QerInfo, urr::UrrInfo,
};

#[derive(Clone)]
pub struct PfcpSession {
    cp_seid: u64,
    ue_ipv4: Option<Ipv4Addr>,          // key into eBPF DL PDRs
    ue_ipv6: Option<Ipv6Addr>,          // key into eBPF DL PDRs
    teid: Option<u32>,                  // key into eBPF UL PDRs
    remote_nodeid: String,              // key to access entry in ctx.associations
    pub ul_pdrs: HashMap<u16, PdrInfo>, // key: pdr id
    pub dl_pdrs: HashMap<u16, PdrInfo>, // key: pdr id
    pub fars: HashMap<u32, FarInfo>,    // key: far id
    pub qers: HashMap<u32, QerInfo>,
    pub urrs: HashMap<u32, UrrInfo>,
}

impl PfcpSession {
    pub fn new(remote_nodeid: String, cp_seid: u64) -> Self {
        Self {
            cp_seid,
            remote_nodeid,
            ul_pdrs: HashMap::new(),
            dl_pdrs: HashMap::new(),
            fars: HashMap::new(),
            qers: HashMap::new(),
            urrs: HashMap::new(),
            ue_ipv4: None,
            ue_ipv6: None,
            teid: None,
        }
    }

    pub fn ue_ipv4(&self) -> Option<Ipv4Addr> {
        self.ue_ipv4
    }

    pub fn set_ue_ipv4(&mut self, ip: Ipv4Addr) {
        self.ue_ipv4 = Some(ip);
    }

    pub fn ue_ipv6(&self) -> Option<Ipv6Addr> {
        self.ue_ipv6
    }

    pub fn set_ue_ipv6(&mut self, ip: Ipv6Addr) {
        self.ue_ipv6 = Some(ip);
    }

    pub fn teid(&self) -> Option<u32> {
        self.teid
    }

    pub fn set_teid(&mut self, teid: u32) {
        self.teid = Some(teid);
    }

    pub fn cp_seid(&self) -> u64 {
        self.cp_seid
    }

    pub fn insert_ul_pdr(&mut self, id: u16, info: PdrInfo) -> anyhow::Result<()> {
        if self.ul_pdrs.len() >= PDR_MAP_SIZE {
            bail!("Maximum number of UL PDRs reached");
        }
        self.ul_pdrs.insert(id, info);
        Ok(())
    }

    pub fn insert_dl_pdr(&mut self, id: u16, info: PdrInfo) -> anyhow::Result<()> {
        if self.dl_pdrs.len() >= PDR_MAP_SIZE {
            bail!("Maximum number of DL PDRs reached");
        }
        self.dl_pdrs.insert(id, info);
        Ok(())
    }

    pub fn insert_far(&mut self, id: u32, info: FarInfo) -> anyhow::Result<()> {
        if self.fars.len() >= FAR_MAP_SIZE {
            bail!("Maximum number of FARs reached");
        }
        self.fars.insert(id, info);
        Ok(())
    }

    pub fn insert_qer(&mut self, id: u32, info: QerInfo) -> anyhow::Result<()> {
        if self.qers.len() >= QER_MAP_SIZE {
            bail!("Maximum number of QERs reached");
        }
        self.qers.insert(id, info);
        Ok(())
    }

    pub fn insert_urr(&mut self, id: u32, info: UrrInfo) -> anyhow::Result<()> {
        if self.urrs.len() >= URR_MAP_SIZE {
            bail!("Maximum number of URRs reached");
        }
        self.urrs.insert(id, info);
        Ok(())
    }
}
