use std::fs::File;
use std::io;
use std::io::{BufReader, ErrorKind};
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys};
use crate::authentication;


pub(crate) const SHA1_DIGEST_SIZE: usize = 20;


pub(crate) fn hex_dump(buf: &[u8]) -> String {
    buf.iter()
        .fold(
            String::with_capacity(2 * buf.len()),
            |str, b| str + format!("{:02x}", b).as_str()
        )
}

pub(crate) fn hex_dump_uppercase(buf: &[u8]) -> String {
    buf.iter()
        .fold(
            String::with_capacity(2 * buf.len()),
            |str, b| str + format!("{:02X}", b).as_str()
        )
}

pub(crate) fn load_certs(filename: &str) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(filename)?))
        .map_err(|e| io::Error::new(
            ErrorKind::InvalidInput, format!("Invalid cert: {}", e)))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

pub(crate) fn load_private_key(filename: &str) -> io::Result<PrivateKey> {
    pkcs8_private_keys(&mut BufReader::new(File::open(filename)?))
        .map_err(|e| io::Error::new(
            ErrorKind::InvalidInput, format!("Invalid key: {}", e)))
        .map(|mut keys| PrivateKey(keys.remove(0)))
}

pub(crate) fn scan_sni_authentication<'a>(sni: &'a str, hostname: &str) -> Option<authentication::Source<'a>> {
    sni.strip_suffix(hostname)
        .and_then(|seek| seek.strip_suffix('.'))
        .map(|x| authentication::Source::Sni(x.into()))
}
