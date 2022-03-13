use std::ffi::c_void;

use foreign_types::ForeignType;
use openssl::{
    asn1::Asn1Time,
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Private},
    rsa::Rsa,
    x509::{X509Builder, X509NameBuilder, X509},
};

pub struct CertKey {
    key: PKey<Private>,
    cert: X509,
}

#[no_mangle]
pub extern "C" fn cert_key_new() -> *mut CertKey {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let cert = gen_self_signed_cert(&pkey).unwrap();

    let cert_key = Box::new(CertKey {
        key: pkey,
        cert: cert,
    });

    Box::into_raw(cert_key)
}

#[no_mangle]
pub extern "C" fn cert_key_free(p: *mut CertKey) {
    unsafe { Box::from_raw(p) };
}

#[no_mangle]
pub extern "C" fn cert_key_get_key(p: *mut CertKey) -> *mut c_void {
    let cert_key = unsafe { &*p };
    // FIXME: returns void pointer to simplify Dart->C bindings generation,
    // since this code won't be used later, it's ok atm
    cert_key.key.as_ptr().cast()
}

#[no_mangle]
pub extern "C" fn cert_key_get_cert(p: *mut CertKey) -> *mut c_void {
    let cert_key = unsafe { &*p };
    // FIXME: ditto
    cert_key.cert.as_ptr().cast()
}

fn gen_self_signed_cert(pkey: &PKeyRef<Private>) -> Result<X509, ErrorStack> {
    let names = vec![
        ("C", "CZ"),
        ("ST", "CZ"),
        ("O", "MeeSign app, DECT 2021-2025"),
        ("CN", "MeeSign app, DECT 2021-2025"),
    ];

    let mut name_builder = X509NameBuilder::new()?;
    for (field, value) in names {
        name_builder.append_entry_by_text(field, value)?;
    }
    let name = name_builder.build();

    let mut builder = X509Builder::new()?;
    builder.set_subject_name(&name)?;
    let before = Asn1Time::days_from_now(0)?;
    let after = Asn1Time::days_from_now(365)?;
    builder.set_not_before(&before)?;
    builder.set_not_after(&after)?;
    builder.set_pubkey(pkey)?;
    builder.sign(pkey, MessageDigest::sha256())?;
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
