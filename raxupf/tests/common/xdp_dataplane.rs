use aya::{TestRun, TestRunOptions};
use aya_ebpf::bindings::xdp_action;

mod common;

#[tokio::test]
async fn transmits_valid_gtpu_ipv4() {
    // // 1. Arrange (build a packet and construct the ops)
    // let mut ebpf = load_ebpf().unwrap();
    // let mut setup_result = setup_test_xdp_progs(&mut ebpf, "").unwrap();
    // let xdp_prog = setup_result.xdp_prog();
    //
    // let input_data = [0u8; 64];
    // let mut output_data = [0u8; 64];
    // let opts = TestRunOptions {
    //     data_in: Some(&input_data),
    //     data_out: Some(&mut output_data),
    //     repeat: 1,
    //     ..Default::default()
    // };
    //
    // // 2. Act (run the BPF_PROG_TEST_RUN)
    // let result = xdp_prog.test_run(opts).unwrap();
    // println!(
    //     "Program returned: {}, took {} ns",
    //     result.return_value,
    //     result.duration.as_nanos()
    // );
    //
    // // 3. Assert (check the returned code)
    // assert_eq!(result.return_value, xdp_action::XDP_PASS);
}

#[tokio::test]
async fn encapsulates_into_gtpu_ipv4_udp() {}

#[tokio::test]
async fn routes_ipv4_successfully() {}
