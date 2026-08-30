//! Parse and verify PCK certificate chains
//!
//! What this establishes: every certificate in the chain is signed by the next one, the names chain
//! up, each issuer is a CA that is allowed to sign certificates, the leaf is not a CA, and the chain
//! terminates at the pinned Intel root CA. With a time supplied, it also establishes that no
//! certificate in the chain is outside its validity period.
//!
//! What it does not establish, because both need data that has to be fetched from Intel over the
//! network and this crate is `no_std` and dependency-light: that no certificate has been revoked
//! (Intel publishes CRLs for the root and intermediate CAs), and that the platform's TCB is up to
//! date (which requires the leaf's FMSPC extension to be evaluated against Intel's TCB info). A
//! caller that needs either must do it separately - a revoked or out-of-date platform passes the
//! checks here.
mod error;

use alloc::vec::Vec;
pub use error::PckParseVerifyError;
use x509_verify::{
    der::{asn1::ObjectIdentifier, Decode, Encode},
    x509_cert::{
        ext::pkix::{BasicConstraints, KeyUsage, KeyUsages},
        Certificate,
    },
    Signature, VerifyInfo, VerifyingKey,
};

/// Intels root CA certificate in DER format available from here:
/// https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer
/// Valid until December 31 2049
const INTEL_ROOT_CA_DER: &[u8; 659] =
    include_bytes!("Intel_SGX_Provisioning_Certification_RootCA.cer");

/// Upper bound on the size of an encoded certificate chain we are willing to parse.
///
/// A PCK chain is a leaf plus one intermediate, together a few kilobytes. The chain arrives inside
/// an untrusted quote, so without a bound a quote can ask this process to parse an arbitrary amount
/// of PEM.
const MAX_ENCODED_CHAIN_SIZE: usize = 32 * 1024;

/// Upper bound on the number of certificates in a chain, including the appended root.
///
/// A PCK chain is leaf -> intermediate -> root. Anything longer is not a PCK chain, and each extra
/// certificate is another signature verification an untrusted quote can ask for.
const MAX_CHAIN_LENGTH: usize = 4;

/// The `basicConstraints` extension, RFC 5280 section 4.2.1.9.
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
/// The `keyUsage` extension, RFC 5280 section 4.2.1.3.
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

/// Verify a PCK certificate chain against Intel root CA given as PEM certificated concatenated together.
/// This is the format in which it is extracted from the quote
///
/// This does not check the certificates' validity periods, because doing so needs a clock this
/// `no_std` crate does not have. Prefer [`verify_pck_certificate_chain_pem_at`] wherever the current
/// time is available: an expired PCK certificate passes this function.
pub fn verify_pck_certificate_chain_pem(
    pck_certificate_chain_pem: Vec<u8>,
) -> Result<p256::ecdsa::VerifyingKey, PckParseVerifyError> {
    verify_pck_chain_pem_inner(pck_certificate_chain_pem, None)
}

/// Same as [`verify_pck_certificate_chain_pem`], but also requires every certificate in the chain to
/// be within its validity period at `unix_time_seconds` (seconds since the Unix epoch, UTC).
pub fn verify_pck_certificate_chain_pem_at(
    pck_certificate_chain_pem: Vec<u8>,
    unix_time_seconds: u64,
) -> Result<p256::ecdsa::VerifyingKey, PckParseVerifyError> {
    verify_pck_chain_pem_inner(pck_certificate_chain_pem, Some(unix_time_seconds))
}

fn verify_pck_chain_pem_inner(
    pck_certificate_chain_pem: Vec<u8>,
    unix_time_seconds: Option<u64>,
) -> Result<p256::ecdsa::VerifyingKey, PckParseVerifyError> {
    if pck_certificate_chain_pem.len() > MAX_ENCODED_CHAIN_SIZE {
        return Err(PckParseVerifyError::ChainTooLarge);
    }
    let pems = pem::parse_many(pck_certificate_chain_pem)?;
    if pems.len() >= MAX_CHAIN_LENGTH {
        return Err(PckParseVerifyError::TooManyCertificates);
    }
    let ders = pems
        .into_iter()
        .map(|pem| pem.contents().to_vec())
        .collect();
    verify_pck_chain_der_inner(ders, unix_time_seconds)
}

/// Verify a PCK certificate chain against Intel root CA given as a vector of der encoded certificates
///
/// See [`verify_pck_certificate_chain_pem`] for the validity-period caveat.
pub fn verify_pck_certificate_chain_der(
    pck_certificate_chain_der: Vec<Vec<u8>>,
) -> Result<p256::ecdsa::VerifyingKey, PckParseVerifyError> {
    verify_pck_chain_der_inner(pck_certificate_chain_der, None)
}

/// Same as [`verify_pck_certificate_chain_der`], but also requires every certificate in the chain to
/// be within its validity period at `unix_time_seconds` (seconds since the Unix epoch, UTC).
pub fn verify_pck_certificate_chain_der_at(
    pck_certificate_chain_der: Vec<Vec<u8>>,
    unix_time_seconds: u64,
) -> Result<p256::ecdsa::VerifyingKey, PckParseVerifyError> {
    verify_pck_chain_der_inner(pck_certificate_chain_der, Some(unix_time_seconds))
}

fn verify_pck_chain_der_inner(
    pck_certificate_chain_der: Vec<Vec<u8>>,
    unix_time_seconds: Option<u64>,
) -> Result<p256::ecdsa::VerifyingKey, PckParseVerifyError> {
    let pck_uncompressed = verify_pck_cert_chain(pck_certificate_chain_der, unix_time_seconds)?;

    // Compress / convert public key
    let point = p256::EncodedPoint::from_bytes(pck_uncompressed)
        .map_err(|_| PckParseVerifyError::BadPublicKey)?;
    let pck_verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
        .map_err(|_| PckParseVerifyError::BadPublicKey)?;
    Ok(pck_verifying_key)
}

/// Validate PCK and provider certificates and if valid return the PCK
fn verify_pck_cert_chain(
    certificates_der: Vec<Vec<u8>>,
    unix_time_seconds: Option<u64>,
) -> Result<[u8; 65], PckParseVerifyError> {
    if certificates_der.is_empty() {
        return Err(PckParseVerifyError::NoCertificate);
    }
    if certificates_der.len() >= MAX_CHAIN_LENGTH {
        return Err(PckParseVerifyError::TooManyCertificates);
    }

    // Parse the certificates
    let mut certificates = Vec::new();
    for certificate in certificates_der {
        certificates.push(Certificate::from_der(&certificate)?);
    }
    // Add the root certificate to the end of the chain. Since the root cert is self-signed, this
    // will work regardless of whether the user has included this certicate in the chain or not
    certificates.push(Certificate::from_der(INTEL_ROOT_CA_DER)?);

    // Verify the certificate chain
    for i in 0..certificates.len() {
        let is_root = i + 1 == certificates.len();
        let issuer = if is_root {
            // The pinned root is self-signed, so it is its own issuer.
            &certificates[i]
        } else {
            &certificates[i + 1]
        };

        let verifying_key: &VerifyingKey = &issuer
            .tbs_certificate
            .subject_public_key_info
            .clone()
            .try_into()?;
        verify_cert(&certificates[i], verifying_key)?;

        // A valid signature alone does not make a chain. Without the checks below, any certificate
        // signed by Intel's intermediate CA - including a PCK certificate for a different platform,
        // or an end-entity certificate that was never meant to sign anything - could be presented as
        // the issuer of an attacker-generated certificate, and the chain would still verify.

        // Names must chain: the subject's stated issuer has to be the issuer's subject.
        if certificates[i].tbs_certificate.issuer != issuer.tbs_certificate.subject {
            return Err(PckParseVerifyError::IssuerMismatch);
        }

        if let Some(now) = unix_time_seconds {
            check_validity(&certificates[i], now)?;
        }

        if i == 0 {
            // The leaf is an end-entity certificate; if it were a CA, a compromise of the PCK key
            // would also allow issuing further certificates under Intel's root.
            if is_ca(&certificates[i])? {
                return Err(PckParseVerifyError::LeafIsCertificateAuthority);
            }
        } else {
            // Every certificate that issued another one must be allowed to.
            check_can_issue(&certificates[i], i)?;
        }
    }

    // Get the first certificate
    let pck_key = &certificates
        .first()
        .ok_or(PckParseVerifyError::NoCertificate)?
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key;

    Ok(pck_key
        .as_bytes()
        .ok_or(PckParseVerifyError::BadPublicKey)?
        .try_into()?)
}

/// Decode a certificate's `basicConstraints` extension, if it has one
fn basic_constraints(
    certificate: &Certificate,
) -> Result<Option<BasicConstraints>, PckParseVerifyError> {
    let extensions = match &certificate.tbs_certificate.extensions {
        Some(extensions) => extensions,
        None => return Ok(None),
    };
    for extension in extensions.iter() {
        if extension.extn_id == OID_BASIC_CONSTRAINTS {
            return Ok(Some(BasicConstraints::from_der(
                extension.extn_value.as_bytes(),
            )?));
        }
    }
    Ok(None)
}

/// Whether a certificate asserts that it is a certificate authority
fn is_ca(certificate: &Certificate) -> Result<bool, PckParseVerifyError> {
    Ok(basic_constraints(certificate)?
        .map(|constraints| constraints.ca)
        .unwrap_or(false))
}

/// Check that a certificate is permitted to have issued the `depth` certificates below it
fn check_can_issue(
    certificate: &Certificate,
    depth: usize,
) -> Result<(), PckParseVerifyError> {
    let constraints =
        basic_constraints(certificate)?.ok_or(PckParseVerifyError::NotACertificateAuthority)?;
    if !constraints.ca {
        return Err(PckParseVerifyError::NotACertificateAuthority);
    }
    // `pathLenConstraint` counts the intermediate CAs allowed below this one, so a certificate at
    // `depth` has `depth - 1` CAs beneath it.
    if let Some(path_len) = constraints.path_len_constraint {
        if u64::from(path_len) < (depth as u64) - 1 {
            return Err(PckParseVerifyError::PathLengthExceeded);
        }
    }

    // `keyUsage` is optional in a certificate, but when present it is authoritative: an issuer that
    // does not assert `keyCertSign` must not be accepted as one.
    let extensions = match &certificate.tbs_certificate.extensions {
        Some(extensions) => extensions,
        None => return Ok(()),
    };
    for extension in extensions.iter() {
        if extension.extn_id == OID_KEY_USAGE {
            let key_usage = KeyUsage::from_der(extension.extn_value.as_bytes())?;
            if !key_usage.0.contains(KeyUsages::KeyCertSign) {
                return Err(PckParseVerifyError::KeyCertSignNotAllowed);
            }
        }
    }
    Ok(())
}

/// Check that a certificate is within its validity period at the given time
fn check_validity(
    certificate: &Certificate,
    unix_time_seconds: u64,
) -> Result<(), PckParseVerifyError> {
    let validity = &certificate.tbs_certificate.validity;
    if unix_time_seconds < validity.not_before.to_unix_duration().as_secs() {
        return Err(PckParseVerifyError::CertificateNotYetValid);
    }
    if unix_time_seconds > validity.not_after.to_unix_duration().as_secs() {
        return Err(PckParseVerifyError::CertificateExpired);
    }
    Ok(())
}

/// Given a cerificate and a public key, verify the certificate
fn verify_cert(subject: &Certificate, issuer_pk: &VerifyingKey) -> Result<(), PckParseVerifyError> {
    let verify_info = VerifyInfo::new(
        subject.tbs_certificate.to_der()?.into(),
        Signature::new(
            &subject.signature_algorithm,
            subject
                .signature
                .as_bytes()
                .ok_or(PckParseVerifyError::Parse)?,
        ),
    );
    Ok(issuer_pk.verify(&verify_info)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_verify_pck_cert_chain() {
        let pck = include_bytes!("../../test_pck_certs/pck_cert.der").to_vec();
        let platform = include_bytes!("../../test_pck_certs/platform_pcs_cert.der").to_vec();
        assert!(verify_pck_certificate_chain_der(vec![pck, platform]).is_ok());
    }

    #[test]
    fn rejects_a_chain_with_too_many_certificates() {
        let pck = include_bytes!("../../test_pck_certs/pck_cert.der").to_vec();
        let chain = vec![pck.clone(), pck.clone(), pck.clone(), pck];
        assert_eq!(
            verify_pck_certificate_chain_der(chain),
            Err(PckParseVerifyError::TooManyCertificates)
        );
    }

    #[test]
    fn rejects_an_expired_chain() {
        let pck = include_bytes!("../../test_pck_certs/pck_cert.der").to_vec();
        let platform = include_bytes!("../../test_pck_certs/platform_pcs_cert.der").to_vec();
        // A time far enough in the future that no PCK certificate can still be valid.
        let year_2100 = 4_102_444_800;
        assert_eq!(
            verify_pck_certificate_chain_der_at(vec![pck, platform], year_2100),
            Err(PckParseVerifyError::CertificateExpired)
        );
    }
}
