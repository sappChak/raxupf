use log::debug;
use raxupf_common::qer::{GateStatus, Gbr, Mbr, QerInfo};
use rs_pfcp::ie::{create_qer::CreateQer, gate_status::GateStatusValue, update_qer::UpdateQer};

use crate::session::PfcpSession;

pub fn create_qer_rule(received_qer: CreateQer, session: &mut PfcpSession) -> anyhow::Result<()> {
    debug!("Incoming QER: {:?}", received_qer);
    let id = received_qer.qer_id.value;
    let mut info = QerInfo::default();

    if let Some(status) = received_qer.gate_status {
        match status.downlink_gate {
            GateStatusValue::Open => info.set_dl_gate_status(GateStatus::Open),
            GateStatusValue::Closed => info.set_dl_gate_status(GateStatus::Closed),
        }

        match status.uplink_gate {
            GateStatusValue::Open => info.set_ul_gate_status(GateStatus::Open),
            GateStatusValue::Closed => info.set_ul_gate_status(GateStatus::Closed),
        }
    }

    if let Some(qfi) = received_qer.qfi {
        info.set_qfi(qfi.value());
    }

    if let Some(mbr) = received_qer.mbr {
        let mbr = Mbr::new(mbr.uplink, mbr.downlink);
        info.set_mbr(mbr);
    }

    if let Some(gbr) = received_qer.gbr {
        let gbr = Gbr::new(gbr.uplink, gbr.downlink);
        info.set_gbr(gbr);
    }

    session.insert_qer(id, info)
}

pub fn update_qer_rule(received_qer: UpdateQer, session: &mut PfcpSession) {}

pub fn remove_qer_rule(qer_id: u32) {}
