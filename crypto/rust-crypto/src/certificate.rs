//! Self-signed DTLS certificates with RustCrypto only.
//!
//! dimpl's `rcgen` feature would generate them with rcgen on aws-lc-rs, which
//! pulls C code into an otherwise pure Rust backend.

use std::str::FromStr;
use std::time::Duration;

use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::EncodePrivateKey;
use rand_core::{OsRng, RngCore};
use str0m_proto::crypto::dtls::DtlsCert;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::Encode;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

/// How long a generated certificate is valid.
const VALIDITY: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// An ECDSA P-256 certificate valid for a year, like dimpl's rcgen-based one:
/// subject `CN=DTLS Peer, O=DTLS`, a random serial number, not a CA. The
/// private key is PKCS#8 DER.
pub(crate) fn generate() -> Option<DtlsCert> {
    let key = SigningKey::random(&mut OsRng);
    let public_key = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).ok()?;
    let subject = Name::from_str("CN=DTLS Peer,O=DTLS").ok()?;

    // Unique across processes and machines (Firefox rejects repeated serial
    // numbers, see str0m#517); positive, as DER integers are signed.
    let mut serial = [0u8; 16];
    OsRng.fill_bytes(&mut serial);
    serial[0] &= 0x7f;
    let serial = SerialNumber::new(&serial).ok()?;

    let validity = Validity::from_now(VALIDITY).ok()?;
    let builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        serial,
        validity,
        subject,
        public_key,
        &key,
    )
    .ok()?;
    let certificate = builder.build::<DerSignature>().ok()?.to_der().ok()?;
    let private_key = key.to_pkcs8_der().ok()?.as_bytes().to_vec();
    Some(DtlsCert {
        certificate,
        private_key,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::DecodePrivateKey;
    use x509_cert::Certificate;
    use x509_cert::der::Decode;

    #[test]
    fn generates_a_self_signed_p256_certificate() {
        let cert = generate().expect("a certificate");
        let parsed = Certificate::from_der(&cert.certificate).expect("valid DER");
        let tbs = &parsed.tbs_certificate;
        assert_eq!(tbs.subject.to_string(), "CN=DTLS Peer,O=DTLS");
        assert_eq!(tbs.issuer, tbs.subject);
        assert_eq!(
            tbs.signature.oid,
            x509_cert::der::oid::db::rfc5912::ECDSA_WITH_SHA_256
        );

        // Signed by the key that comes with it.
        let key = SigningKey::from_pkcs8_der(&cert.private_key).expect("PKCS#8 key");
        let verifying = VerifyingKey::from(&key);
        let signature = DerSignature::try_from(parsed.signature.raw_bytes()).unwrap();
        verifying
            .verify(&tbs.to_der().unwrap(), &signature)
            .expect("self-signed");

        // A new serial number every time.
        let other = Certificate::from_der(&generate().unwrap().certificate).unwrap();
        assert_ne!(other.tbs_certificate.serial_number, tbs.serial_number);
    }
}
