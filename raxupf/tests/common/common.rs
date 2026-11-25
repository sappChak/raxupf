#![allow(unused_variables)]

use std::sync::Arc;

use raxupf::{
    BpfMaps, StoreRules,
    configuration::config::get_configuration,
    loader::{LoadResult, load_ebpf, load_xdp_progs},
    pfcp::PfcpContext,
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

pub struct TestSetup<'a> {
    pub ctx: Arc<PfcpContext>,
    pub _ebpf: Option<aya::Ebpf>,
    pub xdp: Option<LoadResult<'a>>,
}

impl<'a> TestSetup<'a> {
    pub fn ctx(&self) -> &PfcpContext {
        &self.ctx
    }
}

pub async fn spawn_cp_test_setup<'a>() -> anyhow::Result<TestSetup<'a>> {
    let configuration = get_configuration().unwrap();

    assert_eq!(configuration.pfcp.node_id, "172.20.0.1".to_string());
    assert_eq!(configuration.pfcp.local_addr, "172.20.0.1".to_string());
    assert_eq!(configuration.gtpu.mode, "generic".to_string());

    let ebpf = load_ebpf().await?;
    let maps = Arc::new(MockMaps {});

    let ctx = PfcpContext::new(maps, &configuration).await?;
    Ok(TestSetup {
        ctx,
        _ebpf: Some(ebpf),
        xdp: None,
    })
}

pub async fn spawn_dataplane_test_setup<'a>(
    ebpf: &'a mut aya::Ebpf,
) -> anyhow::Result<TestSetup<'a>> {
    let configuration = get_configuration().unwrap();

    assert_eq!(configuration.pfcp.node_id, "172.20.0.1".to_string());
    assert_eq!(configuration.pfcp.local_addr, "172.20.0.1".to_string());
    assert_eq!(configuration.gtpu.mode, "generic".to_string());

    let maps = Arc::new(BpfMaps::new(ebpf)?);
    let load_result = load_xdp_progs(ebpf)?;

    let ctx = PfcpContext::new(maps, &configuration).await?;
    Ok(TestSetup {
        ctx,
        _ebpf: None,
        xdp: Some(load_result),
    })
}
