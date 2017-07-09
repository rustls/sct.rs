
#![forbid(unsafe_code,
          unstable_features)]
#![deny(trivial_casts,
        trivial_numeric_casts,
//        missing_docs,
        unused_import_braces,
        unused_extern_crates,
        unused_qualifications)]

extern crate ring;
extern crate untrusted;

use std::io::Write;

/// Describes a CT log
#[derive(Debug)]
pub struct Log<'a> {
    description: &'a str,
    url: &'a str,
    operated_by: &'a str,
    key: &'a [u8],
    id: [u8; 32],
    mmd: usize
}

impl<'a> Log<'a> {
    pub fn get_log_id(&self) -> [u8; 32] {
        let mut ret = [0u8; 32];
        let d = ring::digest::digest(&ring::digest::SHA256, self.key);
        ret.as_mut()
            .write_all(d.as_ref())
            .unwrap();
        ret
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Error {
    MalformedSCT,
    UnsupportedSCTVersion,
    InvalidSignature,
    InvalidKey,
    SCTTimestampInFuture,
    UnknownLog,
}

fn lookup(logs: &[&Log], id: &[u8]) -> Result<usize, Error> {
    for (i, l) in logs.iter().enumerate() {
        if id == &l.id {
            return Ok(i);
        }
    }

    Err(Error::UnknownLog)
}

fn decode_u64(inp: untrusted::Input) -> u64 {
    let b = inp.as_slice_less_safe();
    assert_eq!(b.len(), 8);
    (b[0] as u64) << 56 |
        (b[1] as u64) << 48 |
        (b[2] as u64) << 40 |
        (b[3] as u64) << 32 |
        (b[4] as u64) << 24 |
        (b[5] as u64) << 16 |
        (b[6] as u64) << 8 |
        (b[7] as u64)
}

fn decode_u16(inp: untrusted::Input) -> u16 {
    let b = inp.as_slice_less_safe();
    assert_eq!(b.len(), 2);
    (b[0] as u16) << 8 | (b[1] as u16)
}

fn write_u64(v: u64, out: &mut Vec<u8>) {
    out.push((v >> 56) as u8);
    out.push((v >> 48) as u8);
    out.push((v >> 40) as u8);
    out.push((v >> 32) as u8);
    out.push((v >> 24) as u8);
    out.push((v >> 16) as u8);
    out.push((v >> 8) as u8);
    out.push(v as u8);
}

fn write_u24(v: u32, out: &mut Vec<u8>) {
    out.push((v >> 16) as u8);
    out.push((v >> 8) as u8);
    out.push(v as u8);
}

#[derive(Debug)]
struct SCT<'a> {
    log_id: &'a [u8],
    timestamp: u64,
    sig_alg: u16,
    sig: &'a [u8],
}

const ECDSA_NISTP256_SHA256: u16 = 0x0403;
const SCT_V1: u8 = 0u8;
const SCT_TIMESTAMP: u8 = 0u8;
const SCT_X509_ENTRY: [u8; 2] = [0, 0];
const SCT_NO_EXTENSION: [u8; 2] = [0, 0];

impl<'a> SCT<'a> {
    fn verify(&self, key: &[u8], cert: &[u8]) -> Result<(), Error> {
        let alg = match self.sig_alg {
            ECDSA_NISTP256_SHA256 => &ring::signature::ECDSA_P256_SHA256_ASN1,
            _ => return Err(Error::InvalidSignature)
        };

        let mut data = Vec::new();
        data.push(SCT_V1);
        data.push(SCT_TIMESTAMP);
        write_u64(self.timestamp, &mut data);
        data.extend_from_slice(&SCT_X509_ENTRY);
        write_u24(cert.len() as u32, &mut data);
        data.extend_from_slice(cert);
        data.extend_from_slice(&SCT_NO_EXTENSION);

        let sig = untrusted::Input::from(self.sig);
        let data = untrusted::Input::from(&data);
        let key = untrusted::Input::from(key);

        ring::signature::verify(alg, key, data, sig)
            .map_err(|_| Error::InvalidSignature)
    }

    fn parse(enc: &'a [u8]) -> Result<SCT<'a>, Error> {
        let inp = untrusted::Input::from(enc);

        inp.read_all(
            Error::MalformedSCT,
            |rd| {
                let version = rd.read_byte()
                    .map_err(|_| Error::MalformedSCT)?;
                if version != 0 {
                    return Err(Error::UnsupportedSCTVersion);
                }

                let id = rd.skip_and_get_input(32)
                    .map_err(|_| Error::MalformedSCT)?;
                let timestamp = rd.skip_and_get_input(8)
                    .map_err(|_| Error::MalformedSCT)
                    .map(decode_u64)?;
                let ext_len = rd.skip_and_get_input(2)
                    .map_err(|_| Error::MalformedSCT)
                    .map(decode_u16)?;

                if ext_len != 0 {
                    return Err(Error::UnsupportedSCTVersion);
                }

                let sig_alg = rd.skip_and_get_input(2)
                    .map_err(|_| Error::MalformedSCT)
                    .map(decode_u16)?;
                let sig_len = rd.skip_and_get_input(2)
                    .map_err(|_| Error::MalformedSCT)
                    .map(decode_u16)?;
                let sig = rd.skip_and_get_input(sig_len as usize)
                    .map_err(|_| Error::MalformedSCT)?;

                let ret = SCT {
                    log_id: id.as_slice_less_safe(),
                    timestamp: timestamp,
                    sig_alg: sig_alg,
                    sig: sig.as_slice_less_safe(),
                };

                Ok(ret)
            })
    }
}

pub fn verify_sct(cert: &[u8], encoded_sct: &[u8], at_time: u64, logs: &[&Log]) -> Result<usize, Error> {
    let sct = SCT::parse(encoded_sct)?;
    let i = lookup(logs, &sct.log_id)?;
    let log = logs[i];
    sct.verify(log.key, cert)?;

    if sct.timestamp > at_time {
        return Err(Error::SCTTimestampInFuture);
    }

    Ok(i)
}

#[cfg(test)]
mod tests {
    static GOOGLE_PILOT: super::Log = super::Log {
        description: "Google 'Pilot' log",
        url: "ct.googleapis.com/pilot/",
        operated_by: "Google",
        key: include_bytes!("testdata/google-pilot-pubkey.bin"),
        id: [164, 185, 9, 144, 180, 24, 88, 20, 135, 187, 19, 162, 204, 103, 112, 10, 60, 53, 152, 4, 249, 27, 223, 184, 227, 119, 205, 14, 200, 13, 220, 16],
        mmd: 86400,
    };

    #[test]
    fn it_works() {
        let sct = include_bytes!("testdata/google-sct0.bin");
        let cert = include_bytes!("testdata/google-cert.bin");
        let logs = [&GOOGLE_PILOT];
        let now = 1499619463644;

        super::verify_sct(cert, sct, now, &logs)
            .unwrap();
    }
}
