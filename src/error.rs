use core::fmt::{self, Display};
use core::num::TryFromIntError;

/// An error when parsing a quote
#[derive(Debug, Eq, PartialEq)]
pub enum QuoteParseError {
    Parse,
    Verification,
    UnknownCertificationDataType,
    UnknownQuoteVersion,
    IntConversionError,
    UnsupportedAttestationKeyType,
    AttestationKeyDoesNotMatch,
}

impl Display for QuoteParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuoteParseError::Parse => f.write_str("Cannot parse quote"),
            QuoteParseError::Verification => f.write_str("Signature is invalid"),
            QuoteParseError::UnknownCertificationDataType => {
                f.write_str("Unknown certification data type")
            }
            QuoteParseError::UnknownQuoteVersion => f.write_str("Unknown quote version"),
            QuoteParseError::IntConversionError => f.write_str("Integer conversion error"),
            QuoteParseError::UnsupportedAttestationKeyType => {
                f.write_str("Unsupported attestion key type")
            }
            QuoteParseError::AttestationKeyDoesNotMatch => {
                f.write_str("Attestation key does not match hash in QE report")
            }
        }
    }
}

impl From<nom::Err<nom::error::Error<&[u8]>>> for QuoteParseError {
    fn from(_: nom::Err<nom::error::Error<&[u8]>>) -> QuoteParseError {
        QuoteParseError::Parse
    }
}

impl From<p256::ecdsa::Error> for QuoteParseError {
    fn from(_: p256::ecdsa::Error) -> QuoteParseError {
        QuoteParseError::Verification
    }
}

impl From<TryFromIntError> for QuoteParseError {
    fn from(_: TryFromIntError) -> QuoteParseError {
        QuoteParseError::IntConversionError
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum QuoteVerificationError {
    NoQeReportCertificationData,
    BadSignature,
}

impl From<p256::ecdsa::Error> for QuoteVerificationError {
    fn from(_: p256::ecdsa::Error) -> QuoteVerificationError {
        QuoteVerificationError::BadSignature
    }
}

/// An error when handling a verifying key
#[derive(Debug, Eq, PartialEq)]
pub enum VerifyingKeyError {
    DecodeEncodedPoint,
    EncodedPointToVerifyingKey,
    BadSize,
}

impl Display for VerifyingKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyingKeyError::DecodeEncodedPoint => {
                f.write_str("Could not decode to encoded point")
            }
            VerifyingKeyError::EncodedPointToVerifyingKey => {
                f.write_str("Could not convert encoded point to verifying key")
            }
            VerifyingKeyError::BadSize => f.write_str("Compressed point has unexpected size"),
        }
    }
}
