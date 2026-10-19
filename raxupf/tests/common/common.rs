use std::sync::{Arc, LazyLock};

use raxupf::{
    configuration::config::{Configuration, get_configuration},
    pfcp::PfcpContext,
};

pub static CONFIGURATION: LazyLock<Configuration> = LazyLock::new(|| get_configuration().unwrap());

pub struct TestSetup {
    pub ctx: Arc<PfcpContext>,
}

pub async fn test_setup(ebpf: &mut aya::Ebpf) -> anyhow::Result<TestSetup> {
    let configuration = &*CONFIGURATION;

    assert_eq!(configuration.pfcp.node_id, "172.20.0.1".to_string());
    assert_eq!(configuration.pfcp.local_addr, "172.20.0.1".to_string());
    assert_eq!(configuration.gtpu.mode, "generic".to_string());

    let ctx = PfcpContext::new(ebpf, configuration).await?;
    Ok(TestSetup { ctx })
}
