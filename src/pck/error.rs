use core::{
    array::TryFromSliceError,
    fmt::{self, Display},
};

/// An error when parsing or verifying a PCK or provider certificate
#[derive(Debug, PartialEq, Eq)]
pub enum PckParseVerifyError {
    Parse,
    Verify,
    BadPublicKey,
    NoCertificate,
    Pem,
    /// The encoded chain is larger than this crate is willing to parse.
    ChainTooLarge,
    /// The chain contains more certificates than a PCK chain ever needs.
    TooManyCertificates,
    /// A certificate's issuer name does not match its issuer's subject name.
    IssuerMismatch,
    /// An issuing certificate is not marked as a certificate authority.
    NotACertificateAuthority,
    /// An issuing certificate does not allow certificate signing.
    KeyCertSignNotAllowed,
    /// The leaf (PCK) certificate is marked as a certificate authority.
    LeafIsCertificateAuthority,
    /// An issuing certificate's `pathLenConstraint` is too small for the chain it signed.
    PathLengthExceeded,
    /// A certificate's validity period has not started at the given time.
    CertificateNotYetValid,
    /// A certificate's validity period ended before the given time.
    CertificateExpired,
}

impl Display for PckParseVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PckParseVerifyError::Parse => f.write_str("Cannot parse PCK certificate"),
            PckParseVerifyError::Verify => f.write_str("Cannot verify PCK certificate"),
            PckParseVerifyError::BadPublicKey => f.write_str("Bad public key"),
            PckParseVerifyError::NoCertificate => f.write_str("No certificate chain given"),
            PckParseVerifyError::Pem => f.write_str("Unable to decode PEM"),
            PckParseVerifyError::ChainTooLarge => {
                f.write_str("Encoded certificate chain is too large")
            }
            PckParseVerifyError::TooManyCertificates => {
                f.write_str("Certificate chain contains too many certificates")
            }
            PckParseVerifyError::IssuerMismatch => {
                f.write_str("Certificate issuer name does not match the issuer's subject name")
            }
            PckParseVerifyError::NotACertificateAuthority => {
                f.write_str("Issuing certificate is not a certificate authority")
            }
            PckParseVerifyError::KeyCertSignNotAllowed => {
                f.write_str("Issuing certificate is not allowed to sign certificates")
            }
            PckParseVerifyError::LeafIsCertificateAuthority => {
                f.write_str("PCK certificate is marked as a certificate authority")
            }
            PckParseVerifyError::PathLengthExceeded => {
                f.write_str("Certificate chain is longer than a pathLenConstraint allows")
            }
            PckParseVerifyError::CertificateNotYetValid => {
                f.write_str("Certificate is not yet valid")
            }
            PckParseVerifyError::CertificateExpired => f.write_str("Certificate has expired"),
        }
    }
}

impl From<spki::der::Error> for PckParseVerifyError {
    fn from(_: spki::der::Error) -> PckParseVerifyError {
        PckParseVerifyError::Parse
    }
}

impl From<x509_verify::Error> for PckParseVerifyError {
    fn from(_: x509_verify::Error) -> PckParseVerifyError {
        PckParseVerifyError::Verify
    }
}

impl From<TryFromSliceError> for PckParseVerifyError {
    fn from(_: TryFromSliceError) -> PckParseVerifyError {
        PckParseVerifyError::BadPublicKey
    }
}

impl From<pem::PemError> for PckParseVerifyError {
    fn from(_: pem::PemError) -> PckParseVerifyError {
        PckParseVerifyError::Pem
    }
}
