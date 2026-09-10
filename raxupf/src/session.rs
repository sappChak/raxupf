use std::{collections::HashMap, net::SocketAddr};

use anyhow::bail;
use log::{debug, error, warn};
use raxupf_common::{SessionContextPod, far::FarInfo, pdr::PdrInfo, qer::QerInfo, urr::UrrInfo};
use rs_pfcp::{
    error::PfcpError,
    ie::{cause::CauseValue, fseid::Fseid, node_id::NodeId},
    message::{
        Message, SessionEstablishmentRequest, SessionModificationRequest,
        session_establishment_response::SessionEstablishmentResponseBuilder,
        session_modification_response::SessionModificationResponseBuilder,
    },
};

use crate::{helpers::create_rules, pfcp::PfcpContext};

#[derive(Clone)]
pub struct PfcpSession {
    local_seid: u64,
    remote_seid: u64,
    ul_pdrs: HashMap<u16, PdrInfo>, // key: pdr id
    dl_pdrs: HashMap<u16, PdrInfo>, // key: pdr id
    fars: HashMap<u32, FarInfo>,    // key: far id
    qers: HashMap<u32, QerInfo>,
    urrs: HashMap<u32, UrrInfo>,
}

impl PfcpSession {
    pub fn new(local_seid: u64, remote_seid: u64) -> Self {
        Self {
            local_seid,
            remote_seid,
            ul_pdrs: HashMap::new(),
            dl_pdrs: HashMap::new(),
            fars: HashMap::new(),
            qers: HashMap::new(),
            urrs: HashMap::new(),
        }
    }

    pub fn insert_ul_pdr(&mut self, id: u16, info: PdrInfo) {
        self.ul_pdrs.insert(id, info);
    }

    pub fn insert_dl_pdr(&mut self, id: u16, info: PdrInfo) {
        self.dl_pdrs.insert(id, info);
    }

    pub fn insert_far(&mut self, id: u32, info: FarInfo) {
        self.fars.insert(id, info);
    }

    pub fn compile(&self) -> SessionContextPod {
        let ul_pdrs = todo!();
        let dl_pdrs = todo!();
        SessionContextPod::new(ul_pdrs, dl_pdrs)
    }
}

pub async fn handle_session_establishment_request(
    ctx: &PfcpContext,
    req: &SessionEstablishmentRequest,
    remote_addr: SocketAddr,
) -> anyhow::Result<()> {
    let rseid = match req.fseid.parse::<Fseid>() {
        Ok(fs) => *fs.seid,
        Err(_) => bail!("session establishment request missing SEID"),
    };
    debug!("Session ID: 0x{rseid:016x}");

    let rnode_id = match req.node_id.parse::<NodeId>() {
        Ok(node_id) => match node_id {
            NodeId::IPv4(ipv4_addr) => ipv4_addr.to_string(),
            NodeId::IPv6(ipv6_addr) => ipv6_addr.to_string(),
            NodeId::FQDN(fqdn) => fqdn,
        },
        Err(_) => {
            bail!("Error parsing remote node id");
        }
    };

    let lseid: u64 = if let Some(lseid) = ctx
        .with_association_mut(&rnode_id, |association| association.allocate_lseid())
        .await
    {
        lseid
    } else {
        warn!("session establishment request for non-existing association");
        let response = SessionEstablishmentResponseBuilder::new(
            0,
            req.sequence(),
            CauseValue::MandatoryIeMissing,
        )
        .build()
        .unwrap();
        return ctx.send_response(&response.marshal(), remote_addr).await;
    };

    let mut session = PfcpSession::new(lseid, rseid);

    let created_pdrs = create_rules(ctx, req, &mut session).await?;

    let mut response_builder = SessionEstablishmentResponseBuilder::accepted(rseid, req.sequence())
        .node_id(ctx.local_addr().ip())
        .fseid(rseid, remote_addr.ip());

    // add all created pdrs to the response
    for created_pdr in created_pdrs {
        response_builder = response_builder.created_pdr(created_pdr);
    }

    let res = match response_builder.build() {
        Ok(r) => r,
        Err(PfcpError::MissingMandatoryIe { ie_type, .. }) => {
            error!("Missing mandatory ie {:?} - sending rejection", ie_type);
            let rejection = SessionEstablishmentResponseBuilder::rejected(rseid, req.sequence())
                .node_id(ctx.local_addr().ip())
                .marshal()?;
            ctx.send_to(&rejection, ctx.remote_addr()).await?;
            return Ok(());
        }
        Err(e) => {
            error!("Failed to build session establishment response: {e} - sending rejection");
            let rejection = SessionEstablishmentResponseBuilder::rejected(rseid, req.sequence())
                .node_id(ctx.local_addr().ip())
                .marshal()?;
            ctx.send_to(&rejection, ctx.remote_addr()).await?;
            return Ok(());
        }
    };

    ctx.with_association_mut(&rnode_id, |association| association.insert_session(session))
        .await;
    ctx.send_response(&res.marshal(), remote_addr).await
}

pub async fn handle_session_modification_request(
    ctx: &PfcpContext,
    req: &SessionModificationRequest,
    remote_addr: SocketAddr,
) -> anyhow::Result<()> {
    let up_seid = match req.seid() {
        Some(s) => *s,
        None => {
            eprintln!("ERROR: Session establishment request missing SEID - dropping message");
            return Ok(());
        }
    };

    let rnode_id = match req.node_id.as_ref().unwrap().parse::<NodeId>() {
        Ok(node_id) => match node_id {
            NodeId::IPv4(ipv4_addr) => ipv4_addr.to_string(),
            NodeId::IPv6(ipv6_addr) => ipv6_addr.to_string(),
            NodeId::FQDN(fqdn) => fqdn,
        },
        Err(_) => {
            bail!("Error parsing remote node id");
        }
    };

    // get a cloned version of a session, updated version'll be reinserted later
    let session: PfcpSession = if let Some(session) = ctx
        .with_association(&rnode_id, |association| association.get_session(up_seid))
        .await
    {
        match session {
            Some(session) => session,
            None => {
                warn!("session modification request for non-existing session");
                let rejection = SessionModificationResponseBuilder::new(up_seid, req.sequence())
                    .cause(CauseValue::SessionContextNotFound);
                return ctx.send_response(&rejection.marshal(), remote_addr).await;
            }
        }
    } else {
        warn!("session modification request for non-existing association");
        let response = SessionEstablishmentResponseBuilder::new(
            0,
            req.sequence(),
            CauseValue::MandatoryIeMissing,
        )
        .build()
        .unwrap();
        return ctx.send_response(&response.marshal(), remote_addr).await;
    };

    Ok(())
}
