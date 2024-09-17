#![no_std]
mod error;
#[cfg(feature = "mock")]
mod mock;
mod take_n;

pub use error::QuoteParseError;
use error::{QuoteVerificationError, VerifyingKeyError};
use p256::EncodedPoint;
use take_n::{take16, take2, take20, take384, take48, take64, take8};

extern crate alloc;
use alloc::vec::Vec;

use nom::{
    bytes::complete::take,
    combinator::{map, map_res},
    number::complete::{le_i16, le_i32, le_u16, le_u32},
    sequence::tuple,
    IResult,
};
#[cfg(feature = "mock")]
pub use p256::ecdsa::SigningKey;
pub use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const QUOTE_HEADER_LENGTH: usize = 48;
const V4_QUOTE_BODY_LENGTH: usize = 584;
const V5_QUOTE_BODY_LENGTH: usize = V4_QUOTE_BODY_LENGTH + 64;

/// A TDX Quote
#[derive(Debug, Eq, PartialEq)]
pub struct Quote {
    pub header: QuoteHeader,
    pub body: QuoteBody,
    pub signature: Signature,
    pub attestation_key: VerifyingKey,
    pub certification_data: CertificationData,
}

impl Quote {
    /// Parse and validate a TDX quote
    pub fn from_bytes(original_input: &[u8]) -> Result<Self, QuoteParseError> {
        // Parse header
        let (input, header) = quote_header_parser(original_input)?;
        if header.attestation_key_type != AttestionKeyType::ECDSA256WithP256 {
            return Err(QuoteParseError::UnsupportedAttestationKeyType);
        };
        let body_length = match header.version {
            4 => V4_QUOTE_BODY_LENGTH,
            5 => V5_QUOTE_BODY_LENGTH,
            _ => return Err(QuoteParseError::UnknownQuoteVersion),
        };

        // Get signed data
        let signed_data = &original_input[..QUOTE_HEADER_LENGTH + body_length];

        // Parse body
        let (input, body) = body_parser(input, header.version)?;

        // Signature
        let (input, _signature_section_length) = le_i32(input)?;
        let (input, signature) = take(64u8)(input)?;
        let signature = Signature::from_bytes(signature.into())?;

        // Attestation key
        let (input, attestation_key) = take(64u8)(input)?;
        let attestation_key_bytes = attestation_key;
        let attestation_key = [&[4], attestation_key].concat(); // 0x04 means uncompressed
        let attestation_key = VerifyingKey::from_sec1_bytes(&attestation_key)?;

        // Verify signature
        attestation_key.verify(signed_data, &signature)?;

        // Certification data
        let (input, certification_data_type) = le_i16(input)?;
        let (input, certification_dat_len) = le_i32(input)?;
        let certification_dat_len: usize = certification_dat_len.try_into()?;
        let (_input, certification_data) = take(certification_dat_len)(input)?;
        let certification_data = CertificationData::new(
            certification_data_type,
            certification_data.to_vec(),
            attestation_key_bytes.to_vec(),
        )?;

        Ok(Quote {
            header,
            body,
            signature,
            attestation_key,
            certification_data,
        })
    }

    /// Returns the report data
    pub fn report_input_data(&self) -> [u8; 64] {
        self.body.reportdata
    }

    /// Returns the build-time measurement register
    pub fn mrtd(&self) -> [u8; 48] {
        self.body.mrtd
    }

    /// Returns the QeReportCertificationData if present
    pub fn qe_report_certification_data(&self) -> Option<QeReportCertificationData> {
        if let CertificationData::QeReportCertificationData(qe_report_certification_data) =
            &self.certification_data
        {
            Some(qe_report_certification_data.clone())
        } else {
            None
        }
    }

    /// Attempt to verify the report with a given provisioning certification key (PCK)
    pub fn verify_with_pck(&self, pck: VerifyingKey) -> Result<(), QuoteVerificationError> {
        let qe_report_certification_data = self
            .qe_report_certification_data()
            .ok_or(QuoteVerificationError::NoQeReportCertificationData)?;
        pck.verify(
            &qe_report_certification_data.qe_report[..],
            &qe_report_certification_data.signature,
        )?;
        Ok(())
    }
}

/// Type of TEE used
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum TEEType {
    SGX = 0x00000000,
    TDX = 0x00000081,
}

impl TryFrom<u32> for TEEType {
    type Error = nom::Err<u32>;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x00000000 => Ok(TEEType::SGX),
            0x00000081 => Ok(TEEType::TDX),
            _ => Err(nom::Err::Failure(value)),
        }
    }
}

/// Type of the Attestation Key used by the Quoting Enclave
#[non_exhaustive]
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum AttestionKeyType {
    ECDSA256WithP256 = 2,
    /// Not yet supported by TDX
    ECDSA384WithP384 = 3,
}

impl TryFrom<u16> for AttestionKeyType {
    type Error = nom::Err<u32>;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(Self::ECDSA256WithP256),
            3 => Ok(Self::ECDSA384WithP384),
            _ => Err(nom::Err::Failure(value as u32)),
        }
    }
}

/// A TDX quote header
#[derive(Debug, Eq, PartialEq)]
pub struct QuoteHeader {
    /// Quote version (4 or 5)
    pub version: u16,
    pub attestation_key_type: AttestionKeyType,
    pub tee_type: TEEType,
    /// Currently unused
    pub reserved1: [u8; 2],
    /// Currently unused
    pub reserved2: [u8; 2],
    /// UUID for the quoting enclave vendor
    pub qe_vendor_id: [u8; 16], // Could use Uuid crate
    pub user_data: [u8; 20],
}

/// Version of TDX used to create the quote
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum TDXVersion {
    One,
    OnePointFive,
}

impl TryFrom<u16> for TDXVersion {
    type Error = QuoteParseError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(TDXVersion::One),
            3 => Ok(TDXVersion::OnePointFive),
            _ => Err(QuoteParseError::Parse),
        }
    }
}

/// A TDX quote body
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QuoteBody {
    pub tdx_version: TDXVersion,
    pub tee_tcb_svn: [u8; 16],
    pub mrseam: [u8; 48],
    pub mrsignerseam: [u8; 48],
    pub seamattributes: [u8; 8],
    pub tdattributes: [u8; 8],
    pub xfam: [u8; 8],
    /// Build-time measurement
    pub mrtd: [u8; 48],
    pub mrconfigid: [u8; 48],
    pub mrowner: [u8; 48],
    pub mrownerconfig: [u8; 48],
    /// Runtime extendable measurement register
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
    /// User defined input data
    pub reportdata: [u8; 64],
    // Optional as only for TDX 1.5
    pub tee_tcb_svn_2: Option<[u8; 16]>,
    // Optional as only for TDX 1.5
    pub mrservicetd: Option<[u8; 48]>,
}

/// Data related to certifying the QE Report
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
#[repr(i16)]
pub enum CertificationData {
    PckIdPpidPlainCpusvnPcesvn(Vec<u8>) = 1,
    PckIdPpidRSA2048CpusvnPcesvn(Vec<u8>) = 2,
    PckIdPpidRSA3072CpusvnPcesvn(Vec<u8>) = 3,
    PckLeafCert(Vec<u8>) = 4,
    PckCertChain(Vec<u8>) = 5,
    QeReportCertificationData(QeReportCertificationData) = 6,
    PlatformManifest(Vec<u8>) = 7,
}

impl CertificationData {
    pub fn new(
        certification_data_type: i16,
        data: Vec<u8>,
        attestation_key: Vec<u8>,
    ) -> Result<Self, QuoteParseError> {
        match certification_data_type {
            1 => Ok(Self::PckIdPpidPlainCpusvnPcesvn(data)),
            2 => Ok(Self::PckIdPpidRSA2048CpusvnPcesvn(data)),
            3 => Ok(Self::PckIdPpidRSA3072CpusvnPcesvn(data)),
            4 => Ok(Self::PckLeafCert(data)),
            5 => Ok(Self::PckCertChain(data)),
            6 => Ok(Self::QeReportCertificationData(
                QeReportCertificationData::new(data, attestation_key)?,
            )),
            7 => Ok(Self::PlatformManifest(data)),
            _ => Err(QuoteParseError::UnknownCertificationDataType),
        }
    }
}

/// Certification data which contains a signature from the PCK
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct QeReportCertificationData {
    /// This should contain SHA256(attestation_public_key || QE authentication data) || 32 null from_bytes
    pub qe_report: [u8; 384],
    /// Signature of the qe_report field made using the PCK key
    pub signature: Signature,
    /// Authentication data used by the quoting enclave to provide additional context
    pub qe_authentication_data: Vec<u8>,
    /// Data required to verify the QE report signature
    pub certification_data: Vec<u8>,
}

impl QeReportCertificationData {
    /// Parse QeReportCertificationData from given input, checking the hash contains the given
    /// attestation key
    fn new(input: Vec<u8>, attestation_key: Vec<u8>) -> Result<Self, QuoteParseError> {
        let (input, qe_report) = take384(&input)?;
        // The last part of the qe_report is the hash of the attestation key and authentication
        // data, followed by 32 null bytes (which we ignore)
        let expected_hash = &qe_report[384 - 64..384 - 32];

        let (input, signature) = take64(&input)?;
        let signature = Signature::from_bytes((&signature).into())?;
        let (input, qe_authentication_data_size) = le_i16(input)?;
        let qe_authentication_data_size: usize = qe_authentication_data_size.try_into()?;
        let (certification_data, qe_authentication_data) =
            take(qe_authentication_data_size)(input)?;

        // Check the hash in the qe_report
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(&attestation_key);
            hasher.update(&qe_authentication_data);
            hasher.finalize()
        };
        if hash[..] != *expected_hash {
            return Err(QuoteParseError::AttestationKeyDoesNotMatch);
        }

        Ok(Self {
            qe_report,
            signature,
            qe_authentication_data: qe_authentication_data.to_vec(),
            certification_data: certification_data.to_vec(),
        })
    }
}

/// Helper function to encode a public key as bytes
pub fn encode_verifying_key(input: &VerifyingKey) -> Result<[u8; 33], VerifyingKeyError> {
    Ok(input
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| VerifyingKeyError::BadSize)?)
}

/// Helper function to decode bytes to a public key
pub fn decode_verifying_key(
    verifying_key_encoded: &[u8; 33],
) -> Result<VerifyingKey, VerifyingKeyError> {
    let point = EncodedPoint::from_bytes(verifying_key_encoded)
        .map_err(|_| VerifyingKeyError::DecodeEncodedPoint)?;
    VerifyingKey::from_encoded_point(&point)
        .map_err(|_| VerifyingKeyError::EncodedPointToVerifyingKey)
}

/// Parser for a quote header
fn quote_header_parser(input: &[u8]) -> IResult<&[u8], QuoteHeader> {
    map_res(
        tuple((le_u16, le_u16, le_u32, take2, take2, take16, take20)),
        |(
            version,
            attestation_key_type,
            tee_type,
            reserved1,
            reserved2,
            qe_vendor_id,
            user_data,
        )| {
            Ok::<QuoteHeader, nom::Err<u32>>(QuoteHeader {
                version,
                attestation_key_type: attestation_key_type.try_into()?,
                tee_type: tee_type.try_into()?,
                reserved1,
                reserved2,
                qe_vendor_id,
                user_data,
            })
        },
    )(input)
}

/// Parser for a quote body
fn body_parser(input: &[u8], version: u16) -> IResult<&[u8], QuoteBody> {
    let (input, tdx_version) = match version {
        // For a version 4 quote format, we know its TDX v1
        4 => (input, TDXVersion::One),
        // For version 5 quote format, read the TDX version from the quote
        5 => {
            let (input, body_type) = le_u16(input)?;
            let (input, _body_size) = le_u32(input)?;
            (
                input,
                body_type.try_into().map_err(|_| {
                    nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Fail))
                })?,
            )
        }
        _ => {
            return Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Fail,
            )))
        }
    };
    // Process the body assuming TDX v1, then add the extra bits for v1.5 if needed
    let (input, mut body) = basic_body_parser(input)?;
    let input = if tdx_version == TDXVersion::OnePointFive {
        body.tdx_version = TDXVersion::OnePointFive;
        let (input, tee_tcb_svn_2) = take16(input)?;
        body.tee_tcb_svn_2 = Some(tee_tcb_svn_2);
        let (input, mrservicetd) = take48(input)?;
        body.mrservicetd = Some(mrservicetd);
        input
    } else {
        input
    };
    Ok((input, body))
}

/// Parser for a quote body - omitting optional extra fields for TDX 1.5
fn basic_body_parser(input: &[u8]) -> IResult<&[u8], QuoteBody> {
    map(
        tuple((
            take16, take48, take48, take8, take8, take8, take48, take48, take48, take48, take48,
            take48, take48, take48, take64,
        )),
        |(
            tee_tcb_svn,
            mrseam,
            mrsignerseam,
            seamattributes,
            tdattributes,
            xfam,
            mrtd,
            mrconfigid,
            mrowner,
            mrownerconfig,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            reportdata,
        )| QuoteBody {
            tdx_version: TDXVersion::One,
            tee_tcb_svn,
            mrseam,
            mrsignerseam,
            seamattributes,
            tdattributes,
            xfam,
            mrtd,
            mrconfigid,
            mrowner,
            mrownerconfig,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            reportdata,
            tee_tcb_svn_2: None,
            mrservicetd: None,
        },
    )(input)
}
