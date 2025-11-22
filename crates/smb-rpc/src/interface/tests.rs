#![cfg(test)]
use smb_rpc_derive::rpc_interface;

use crate::*;

#[rpc_interface(idl = "crates/smb-rpc/src/idl/srvsvc.idl")]
pub struct SrvSvc;
