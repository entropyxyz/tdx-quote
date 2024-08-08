use core::fmt::{self, Display};
use core::num::TryFromIntError;

#[derive(Debug, Eq, PartialEq)]
pub enum QuoteParseError {
    Parse,
    Verification,
    UnknownCertificationDataType,
    UnknownQuoteVersion,
    IntConversionError,
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
