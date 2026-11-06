//! NetrShareEnum (level 1) in the NDR20 transfer syntax (32-bit NDR).
//!
//! Samba (and so TrueNAS, Synology, QNAP) only binds srvsvc in NDR20; Windows
//! takes NDR64 too. The bind offers both, and when the server picked NDR20 the
//! share list is encoded and decoded here, by hand: the request is a handful
//! of fields and the answer one conformant array of `SHARE_INFO_1` with its
//! deferred strings ([MS-SRVS] 3.1.4.8, [C706] chapter 14).

use crate::ndr64::NdrString;
use crate::pdu::DceRpcSyntaxId;
use smb_dtyp::make_guid;

use super::srvsvc::{ShareInfo1, ShareType};

/// The NDR (version 2) transfer syntax: `8a885d04-1ceb-11c9-9fe8-08002b104860` v2.
pub const NDR20_SYNTAX_ID: DceRpcSyntaxId = DceRpcSyntaxId {
    uuid: make_guid!("8a885d04-1ceb-11c9-9fe8-08002b104860"),
    version: 2,
};

/// NetrShareEnum's opnum.
pub const NETR_SHARE_ENUM: u16 = 0xf;

fn align4(buf: &mut Vec<u8>) {
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    align4(buf);
    buf.extend_from_slice(&v.to_le_bytes());
}

/// A conformant varying UTF-16 string, NUL included.
fn put_string(buf: &mut Vec<u8>, s: &str) {
    let units: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    put_u32(buf, units.len() as u32); // max count
    put_u32(buf, 0); // offset
    put_u32(buf, units.len() as u32); // actual count
    for u in units {
        buf.extend_from_slice(&u.to_le_bytes());
    }
    align4(buf);
}

/// The request stub: `NetrShareEnum(ServerName, InfoStruct{level 1, empty
/// container}, PreferedMaximumLength = MAX, ResumeHandle = 0)`.
pub fn netr_share_enum_request(server_name: &str) -> Vec<u8> {
    let mut b = Vec::new();
    // ServerName: [in, string, unique] wchar_t*.
    put_u32(&mut b, 0x0002_0000);
    put_string(&mut b, server_name);
    // InfoStruct: [in, out] LPSHARE_ENUM_STRUCT (a ref pointer: inline).
    put_u32(&mut b, 1); // Level
    put_u32(&mut b, 1); // union switch
    put_u32(&mut b, 0x0002_0004); // SHARE_INFO_1_CONTAINER*
    // ... its pointee, deferred to the end of the parameter.
    put_u32(&mut b, 0); // EntriesRead
    put_u32(&mut b, 0); // Buffer (null)
    // PreferedMaximumLength.
    put_u32(&mut b, u32::MAX);
    // ResumeHandle: [in, out, unique] DWORD*.
    put_u32(&mut b, 0x0002_0008);
    put_u32(&mut b, 0);
    b
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn u32(&mut self) -> crate::Result<u32> {
        self.at = (self.at + 3) & !3;
        let bytes = self
            .data
            .get(self.at..self.at + 4)
            .ok_or(crate::SmbRpcError::InvalidResponseData("NDR20 share list cut short"))?;
        self.at += 4;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn string(&mut self) -> crate::Result<String> {
        let _max = self.u32()?;
        let offset = self.u32()? as usize;
        let actual = self.u32()? as usize;
        let start = self.at + offset * 2;
        let bytes = self
            .data
            .get(start..start + actual * 2)
            .ok_or(crate::SmbRpcError::InvalidResponseData("NDR20 share name cut short"))?;
        self.at = start + actual * 2;
        let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|u| *u != 0).collect();
        Ok(String::from_utf16_lossy(&units))
    }
}

fn ndr_string(s: &str) -> NdrString<u16> {
    s.parse::<NdrString<u16>>().unwrap_or_else(|_| "".parse::<NdrString<u16>>().expect("empty string"))
}

/// The response stub's shares (level 1), or the server's error.
pub fn netr_share_enum_response(stub: &[u8]) -> crate::Result<Vec<ShareInfo1>> {
    let mut r = Reader { data: stub, at: 0 };
    let level = r.u32()?;
    let switch = r.u32()?;
    if level != 1 || switch != 1 {
        return Err(crate::SmbRpcError::InvalidResponseData("NDR20 share list: not level 1"));
    }
    let container = r.u32()?;
    let mut raw: Vec<(u32, u32, u32)> = Vec::new();
    let mut names: Vec<(Option<String>, Option<String>)> = Vec::new();
    if container != 0 {
        let _entries_read = r.u32()?;
        let buffer = r.u32()?;
        if buffer != 0 {
            let count = r.u32()? as usize;
            if count > 65_536 {
                return Err(crate::SmbRpcError::InvalidResponseData("NDR20 share list: too many entries"));
            }
            for _ in 0..count {
                raw.push((r.u32()?, r.u32()?, r.u32()?));
            }
            for (name_ref, _, remark_ref) in &raw {
                let name = if *name_ref != 0 { Some(r.string()?) } else { None };
                let remark = if *remark_ref != 0 { Some(r.string()?) } else { None };
                names.push((name, remark));
            }
        }
    }
    let _total = r.u32()?;
    let resume = r.u32()?;
    if resume != 0 {
        let _ = r.u32()?;
    }
    let status = r.u32()?;
    if status != 0 {
        return Err(crate::SmbRpcError::SendReceiveError(format!("NetrShareEnum failed: WERROR 0x{status:08x}")));
    }
    Ok(raw
        .iter()
        .zip(names)
        .map(|((_, kind, _), (name, remark))| ShareInfo1 {
            netname: name.as_deref().map(ndr_string).into(),
            share_type: ShareType::from_bytes(kind.to_le_bytes()).into(),
            remark: remark.as_deref().map(ndr_string).into(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::ShareKind;

    #[test]
    fn the_request_is_ndr20() {
        let b = netr_share_enum_request(r"\\nas");
        // referent, then max/offset/actual = 6 units ("\\nas" + NUL).
        assert_eq!(&b[0..4], &0x0002_0000u32.to_le_bytes());
        assert_eq!(&b[4..8], &6u32.to_le_bytes());
        assert_eq!(&b[12..16], &6u32.to_le_bytes());
        // 16 + 12 bytes of string, padded to 28; then level 1, switch 1.
        assert_eq!(&b[28..32], &1u32.to_le_bytes());
        assert_eq!(&b[32..36], &1u32.to_le_bytes());
        assert_eq!(b.len() % 4, 0);
        assert_eq!(&b[b.len() - 12..b.len() - 8], &u32::MAX.to_le_bytes());
    }

    /// A Samba answer: Movies (disk), IPC$ (IPC, special), with remarks.
    #[test]
    fn a_samba_answer_decodes() {
        let mut b = Vec::new();
        for v in [1u32, 1, 0x20000, 2, 0x20004, 2] {
            put_u32(&mut b, v);
        }
        // Two SHARE_INFO_1s: refs and types.
        for v in [0x20008u32, 0, 0x2000c, 0x20010, 0x8000_0003, 0x20014] {
            put_u32(&mut b, v);
        }
        put_string(&mut b, "Movies");
        put_string(&mut b, "Films");
        put_string(&mut b, "IPC$");
        put_string(&mut b, "IPC Service (TrueNAS Server)");
        for v in [2u32, 0, 0] {
            put_u32(&mut b, v);
        }
        let shares = netr_share_enum_response(&b).expect("decodes");
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].netname.as_ref().map(|n| n.to_string_lossy()).as_deref(), Some("Movies"));
        assert_eq!(shares[0].remark.as_ref().map(|n| n.to_string_lossy()).as_deref(), Some("Films"));
        assert_eq!(shares[0].share_type.kind(), ShareKind::Disk);
        assert!(!shares[0].share_type.special());
        assert_eq!(shares[1].netname.as_ref().map(|n| n.to_string_lossy()).as_deref(), Some("IPC$"));
        assert_eq!(shares[1].share_type.kind(), ShareKind::IPC);
        assert!(shares[1].share_type.special());
        // An error status is an error.
        let len = b.len();
        b[len - 4..].copy_from_slice(&5u32.to_le_bytes());
        assert!(netr_share_enum_response(&b).is_err());
        // A name beyond ASCII survives.
        assert_eq!(ndr_string("Fotos Ä").to_string_lossy(), "Fotos Ä");
        // Cut short: an error, never a panic.
        assert!(netr_share_enum_response(&b[..20]).is_err());
    }
}
