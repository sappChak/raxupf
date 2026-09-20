use aya::Ebpf;
use raxupf_common::{PDR_MAP_SIZE, far::FarInfo, pdr::PdrInfo, qer::QerInfo, urr::UrrInfo};
use tokio::sync::Mutex;

pub mod association;
pub mod configuration;
pub mod heartbeat;
pub mod iprule_parser;
pub mod pfcp;
pub mod resource_manager;
pub mod rules;
pub mod session;

type AyaHashMap<K, V> = aya::maps::HashMap<aya::maps::MapData, K, V>;

pub type FarMap = AyaHashMap<u32, FarInfo>;

pub type QerMap = AyaHashMap<u32, QerInfo>;

pub type UrrMap = AyaHashMap<u32, UrrInfo>;

pub type UplinkPdrMap = AyaHashMap<u32, [PdrInfo; PDR_MAP_SIZE]>;

pub type DownlinkPdrMap = AyaHashMap<u32, [PdrInfo; PDR_MAP_SIZE]>;

pub struct BpfMaps {
    ul_pdrs: Mutex<UplinkPdrMap>,
    dl_pdrs: Mutex<DownlinkPdrMap>,
    fars: Mutex<FarMap>,
    qers: Mutex<QerMap>,
    urrs: Mutex<UrrMap>,
}

impl BpfMaps {
    pub fn new(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let ul_pdr_map = AyaHashMap::try_from(ebpf.take_map("UL_PDR_MAP").unwrap())?;
        let dl_pdr_map = AyaHashMap::try_from(ebpf.take_map("DL_PDR_MAP").unwrap())?;
        let far_map = AyaHashMap::try_from(ebpf.take_map("FAR_MAP").unwrap())?;
        let qer_map = AyaHashMap::try_from(ebpf.take_map("QER_MAP").unwrap())?;
        let urr_map = AyaHashMap::try_from(ebpf.take_map("URR_MAP").unwrap())?;

        Ok(Self {
            ul_pdrs: Mutex::new(ul_pdr_map),
            dl_pdrs: Mutex::new(dl_pdr_map),
            fars: Mutex::new(far_map),
            qers: Mutex::new(qer_map),
            urrs: Mutex::new(urr_map),
        })
    }

    pub async fn insert_ul_pdr(
        &self,
        teid: u32,
        pdrs: [PdrInfo; PDR_MAP_SIZE],
    ) -> anyhow::Result<()> {
        let mut ul_pdrs = self.ul_pdrs.lock().await;
        ul_pdrs.insert(teid, pdrs, 0)?;
        Ok(())
    }

    pub async fn insert_dl_pdr_ivp4(
        &self,
        ipv4: u32,
        pdrs: [PdrInfo; PDR_MAP_SIZE],
    ) -> anyhow::Result<()> {
        let mut dl_pdrs = self.dl_pdrs.lock().await;
        dl_pdrs.insert(ipv4, pdrs, 0)?;
        Ok(())
    }

    // pub async fn insert_dl_pdr_ivp6(
    //     &self,
    //     ipv6: u128,
    //     pdrs: [PdrInfo; PDR_MAP_SIZE],
    // ) -> anyhow::Result<()> {
    //     let mut dl_pdrs = self.dl_pdrs.lock().await;
    //     dl_pdrs.insert(ipv6, pdrs, 0)?;
    //     Ok(())
    // }

    pub async fn insert_far(&self, far_id: u32, far: FarInfo) -> anyhow::Result<()> {
        let mut fars = self.fars.lock().await;
        fars.insert(far_id, far, 0)?;
        Ok(())
    }

    pub async fn insert_qer(&self, qer_id: u32, qer: QerInfo) -> anyhow::Result<()> {
        let mut qers = self.qers.lock().await;
        qers.insert(qer_id, qer, 0)?;
        Ok(())
    }

    pub async fn insert_urr(&self, urr_id: u32, urr: UrrInfo) -> anyhow::Result<()> {
        let mut urrs = self.urrs.lock().await;
        urrs.insert(urr_id, urr, 0)?;
        Ok(())
    }
}
