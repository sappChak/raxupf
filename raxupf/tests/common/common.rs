use std::sync::Arc;

use raxupf::{
    StoreRules, configuration::config::get_configuration, loader::load_ebpf, pfcp::PfcpContext,
};

pub struct MockMaps {}

impl StoreRules for MockMaps {
    fn insert_ul_pdrs(
        &self,
        teid: u32,
        pdrs: [raxupf_common::pdr::PdrInfo; raxupf_common::PDR_MAP_SIZE],
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn insert_dl_pdrs_ivp4(
        &self,
        ipv4: u32,
        pdrs: [raxupf_common::pdr::PdrInfo; raxupf_common::PDR_MAP_SIZE],
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn insert_dl_pdr_ivp6(
        &self,
        ipv6: u128,
        pdrs: [raxupf_common::pdr::PdrInfo; raxupf_common::PDR_MAP_SIZE],
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn insert_far(&self, far_id: u32, far: raxupf_common::far::FarInfo) -> anyhow::Result<()> {
        Ok(())
    }

    fn insert_qer(&self, qer_id: u32, qer: raxupf_common::qer::QerInfo) -> anyhow::Result<()> {
        Ok(())
    }

    fn insert_urr(&self, urr_id: u32, urr: raxupf_common::urr::UrrInfo) -> anyhow::Result<()> {
        Ok(())
    }
}

pub struct TestSetup {
    pub ctx: Arc<PfcpContext>,
    pub _ebpf: aya::Ebpf,
}

impl TestSetup {
    pub fn ctx(&self) -> &PfcpContext {
        &self.ctx
    }
}

pub async fn spawn_test_setup() -> anyhow::Result<TestSetup> {
    let configuration = get_configuration().unwrap();

    assert_eq!(configuration.pfcp.node_id, "172.20.0.1".to_string());
    assert_eq!(configuration.pfcp.local_addr, "172.20.0.1".to_string());
    assert_eq!(configuration.gtpu.mode, "generic".to_string());

    let ebpf = load_ebpf().await?;
    let maps = Arc::new(MockMaps {});

    let ctx = PfcpContext::new(maps, &configuration).await?;
    Ok(TestSetup { ctx, _ebpf: ebpf })
}
