use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};
use openssl::x509::extension::*;
use openssl::x509::*;

#[allow(clippy::too_many_arguments)]
pub fn generate_root_cert(
    lifetime_days: u32,
    common_name: &Option<String>,
    country: &Option<String>,
    state: &Option<String>,
    locality: &Option<String>,
    organization: &Option<String>,
    organizational_unit: &Option<String>,
    pkey: &PKey<Private>,
) -> X509 {
    let mut x509_builder = X509::builder().unwrap();
    x509_builder.set_version(2).unwrap();

    x509_builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    x509_builder
        .set_not_after(&Asn1Time::days_from_now(lifetime_days).unwrap())
        .unwrap();

    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    x509_builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();

    let mut x509_name_builder = X509Name::builder().unwrap();
    if let Some(cn) = common_name {
        x509_name_builder
            .append_entry_by_nid(Nid::COMMONNAME, cn)
            .unwrap();
    }
    if let Some(c) = country {
        x509_name_builder
            .append_entry_by_nid(Nid::COUNTRYNAME, c)
            .unwrap();
    }
    if let Some(s) = state {
        x509_name_builder
            .append_entry_by_nid(Nid::STATEORPROVINCENAME, s)
            .unwrap();
    }
    if let Some(l) = locality {
        x509_name_builder
            .append_entry_by_nid(Nid::LOCALITYNAME, l)
            .unwrap();
    }
    if let Some(o) = organization {
        x509_name_builder
            .append_entry_by_nid(Nid::ORGANIZATIONNAME, o)
            .unwrap();
    }
    if let Some(ou) = organizational_unit {
        x509_name_builder
            .append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, ou)
            .unwrap();
    }
    let x509_name = x509_name_builder.build();

    x509_builder.set_issuer_name(&x509_name).unwrap();
    x509_builder.set_subject_name(&x509_name).unwrap();

    x509_builder.set_pubkey(pkey).unwrap();

    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    x509_builder.append_extension(basic_constraints).unwrap();

    let key_usage = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()
        .unwrap();
    x509_builder.append_extension(key_usage).unwrap();

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&x509_builder.x509v3_context(None, None))
        .unwrap();
    x509_builder
        .append_extension(subject_key_identifier)
        .unwrap();

    let digest_algorithm = match pkey.id() {
        Id::RSA => MessageDigest::sha256(),
        Id::EC => MessageDigest::sha384(),
        _ => MessageDigest::sha256(),
    };

    x509_builder.sign(pkey, digest_algorithm).unwrap();

    x509_builder.build()
}
