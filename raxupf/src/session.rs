use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use log::{debug, warn};
use raxupf_common::{far::FarInfo, pdr::PdrInfo};
use rs_pfcp::{
    ie::{
        Ie, cause::CauseValue, create_far::CreateFar, create_pdr::CreatePdr, create_qer::CreateQer,
        create_urr::CreateUrr, fseid::Fseid, node_id::NodeId,
    },
    message::{
        Message, SessionEstablishmentRequest,
        session_establishment_response::SessionEstablishmentResponseBuilder,
    },
};
use tokio::{net::UdpSocket, sync::Mutex};

use crate::association::PfcpAssociation;

pub struct PfcpSession {
    local_fseid: u64,
    remote_fseid: u64,
    pdrs: HashMap<u32, PdrInfo>,
    fars: HashMap<u32, FarInfo>,
}

impl PfcpSession {
    pub fn new(local_fseid: u64, remote_fseid: u64) -> Self {
        Self {
            local_fseid,
            remote_fseid,
            pdrs: HashMap::new(),
            fars: HashMap::new(),
        }
    }
}

pub struct SessionPdrInfo {
    pdr_info: PdrInfo,
    allocated: bool,
    qer_idx: usize,
    urr_idx: usize,
}

impl SessionPdrInfo {
    pub fn new(pdr_info: PdrInfo) -> Self {
        Self {
            pdr_info,
            allocated: false,
            qer_idx: 0,
            urr_idx: 0,
        }
    }
}

pub async fn handle_session_establishment_request(
    socket: &UdpSocket,
    buf: &[u8],
    len: usize,
    addr: SocketAddr,
    associations: Arc<Mutex<HashMap<String, PfcpAssociation>>>,
) {
    debug!("incoming session establishment request");
    let req = SessionEstablishmentRequest::unmarshal(&buf[..len]).unwrap();

    let remote_nodeid = match req.node_id.parse::<NodeId>() {
        Ok(node_id) => match node_id {
            NodeId::IPv4(ipv4_addr) => ipv4_addr.to_string(),
            NodeId::IPv6(ipv6_addr) => ipv6_addr.to_string(),
            NodeId::FQDN(fqdn) => fqdn,
        },
        Err(_) => {
            warn!("error parsing node_id");
            todo!()
        }
    };
    debug!("remote node id is: {}", remote_nodeid);

    let mut associations = associations.lock().await;
    if !associations.contains_key(&remote_nodeid) {
        warn!("session establishment request for non-existing association");
        send_session_estab_error_response(socket, 0, &req, CauseValue::MandatoryIeMissing, addr)
            .await;
    }

    let association = if let Some(association) = associations.get_mut(&remote_nodeid) {
        association
    } else {
        warn!("session establishment request for non-existing association");
        send_session_estab_error_response(socket, 0, &req, CauseValue::MandatoryIeMissing, addr)
            .await;
        return;
    };

    let remote_fseid = match req.fseid.parse::<Fseid>() {
        Ok(fseid) => fseid.seid.to_be(),
        Err(_) => todo!(),
    };
    debug!("fseid of the remote node is: {}", remote_fseid);

    let local_seid = association.local_seid();
    let _session = PfcpSession::new(local_seid, remote_fseid);

    // TODO: implement PSUCC, otherwise rollback on failure
    let created_pdrs: Vec<Ie> = Vec::new();

    for create_far in &req.create_fars {
        let far = match create_far.parse::<CreateFar>() {
            Ok(far) => far,
            Err(_) => {
                debug!("error extracting far info");
                todo!()
            }
        };

        let _far_id = far.far_id.value;
    }

    for create_qer in &req.create_urrs {
        let _qer = match create_qer.parse::<CreateQer>() {
            Ok(qer) => qer,
            Err(_) => {
                debug!("error extracting qer info");
                todo!()
            }
        };
    }

    for create_urr in &req.create_urrs {
        let _urr = match create_urr.parse::<CreateUrr>() {
            Ok(urr) => urr,
            Err(_) => {
                debug!("error extracting qer info");
                todo!()
            }
        };
    }

    for create_pdr in &req.create_pdrs {
        let pdr = match create_pdr.parse::<CreatePdr>() {
            Ok(pdr) => pdr,
            Err(_) => {
                todo!();
            }
        };
        let pdr_id = pdr.pdr_id.value;
        let mut sdr_info = SessionPdrInfo::new(PdrInfo::new(pdr_id));

        // if let Some(value) = pdr.outer_header_removal {
        //     sdr_info
        //         .pdr_info
        //         .set_outer_header_removal(value.description);
        // }

        if let Some(value) = pdr.far_id {
            sdr_info.pdr_info.set_far_id(value.value);
        }

        if let Some(value) = pdr.qer_id {
            // TODO: add a boundary check
            sdr_info.pdr_info.set_qer_id(sdr_info.qer_idx, value.value);
            sdr_info.qer_idx += 1;
        }

        if let Some(value) = pdr.urr_id {
            // TODO: add boundary check
            sdr_info.pdr_info.set_urr_id(sdr_info.qer_idx, value.id);
            sdr_info.qer_idx += 1;
        }

        let pdi = pdr.pdi;

        // TODO: implement SDF filter
        // if let Some(sdf_filter) = pdi.sdf_filter {
        // } else {
        //     debug!("SDF filter is empty");
        // }

        if let Some(teid_pdi_id) = pdi.f_teid {
            if teid_pdi_id.ch {}
        }
    }

    let response = SessionEstablishmentResponseBuilder::new(
        remote_fseid,
        req.sequence(),
        CauseValue::RequestAccepted,
    )
    .ies(created_pdrs)
    .build()
    .unwrap();

    let bytes: Vec<u8> = response.marshal();
    if let Ok(n) = socket.send_to(&bytes, addr).await {
        debug!("sent {} bytes to {:?}", n, addr);
    };
}

async fn send_session_estab_error_response(
    socket: &UdpSocket,
    seid: u64,
    req: &SessionEstablishmentRequest,
    cause: CauseValue,
    addr: SocketAddr,
) {
    let response = SessionEstablishmentResponseBuilder::new(seid, req.sequence(), cause)
        .build()
        .unwrap();

    let bytes: Vec<u8> = response.marshal();
    if let Ok(n) = socket.send_to(&bytes, addr).await {
        debug!("sent {} bytes to {:?}", n, addr);
    };
}
