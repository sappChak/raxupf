use std::sync::Arc;

use raxupf::{configuration::config::get_configuration, loader::load_ebpf, pfcp::PfcpContext};

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

    let mut ebpf = load_ebpf().await.unwrap();

    let ctx = PfcpContext::new(&mut ebpf, &configuration).await?;
    Ok(TestSetup { ctx, _ebpf: ebpf })
}
