#![no_std]

pub mod gtpu;
pub mod gtpu_helpers;
pub mod helpers;
pub mod maps;
pub mod message_handlers;
pub mod parser;
pub mod pdr;
pub mod pdu;

pub const GTPU_DST_PORT: u16 = 2152; // per 3GPP TS 29.281 Rel 17
pub const GTP_PROTOCOL_TYPE: u8 = 1; // Distinguish between GTP' and GTP
pub const GTP_VERSION: u8 = 1; // GTP-U is Version 1
pub const MAX_EXT_HDRS: usize = 4;

pub const AF_INET: u8 = 2;
