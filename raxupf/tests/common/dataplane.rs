use aya::{TestRun, TestRunOptions};
use aya_ebpf::bindings::xdp_action;
use raxupf::loader::load_ebpf;

use crate::common::spawn_dataplane_test_setup;

#[tokio::test]
async fn returns_tx_for_valid_session_packet() -> anyhow::Result<()> {
    let mut ebpf = load_ebpf().await?;
    let test_setup = spawn_dataplane_test_setup(&mut ebpf).await?;
    let mut binding = test_setup.xdp.unwrap();
    let xdp_prog = binding.xdp_prog();

    let input_data = [0u8; 64];
    let mut output_data = [0u8; 64];
    let opts = TestRunOptions {
        data_in: Some(&input_data),
        data_out: Some(&mut output_data),
        repeat: 1,
        ..Default::default()
    };

    // 2. Act (run the BPF_PROG_TEST_RUN)
    let result = xdp_prog.test_run(opts).unwrap();
    println!(
        "Program returned: {}, took {} ns",
        result.return_value,
        result.duration.as_nanos()
    );

    // 3. Assert (check the returned code)
    assert_eq!(result.return_value, xdp_action::XDP_PASS);

    Ok(())
}
