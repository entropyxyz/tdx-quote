#![no_std]
mod error;
mod take_n;

pub use error::QuoteParseError;
use take_n::{take16, take2, take20, take48, take64, take8};

extern crate alloc;
use alloc::vec::Vec;

use nom::{
    bytes::complete::take,
    combinator::{map, map_res},
    number::complete::{le_i16, le_i32, le_u16, le_u32},
    sequence::tuple,
    IResult,
};
use p256::ecdsa::{signature::SignerMut, SigningKey};
pub use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

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
        let attestation_key = [&[04], attestation_key].concat(); // 0x04 means uncompressed
        let attestation_key = VerifyingKey::from_sec1_bytes(&attestation_key)?;

        // Verify signature
        attestation_key.verify(signed_data, &signature)?;

        // Certification data
        let (input, certification_data_type) = le_i16(input)?;
        let (input, certification_dat_len) = le_i32(input)?;
        let certification_dat_len: usize = certification_dat_len.try_into()?;
        let (_input, certification_data) = take(certification_dat_len)(input)?;
        let certification_data =
            CertificationData::new(certification_data_type, certification_data.to_vec())?;

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

    pub fn mock(mut signing_key: SigningKey, reportdata: [u8; 64]) -> Self {
        let header = QuoteHeader {
            version: 4,
            attestation_key_type: AttestionKeyType::ECDSA256WithP256,
            tee_type: TEEType::TDX,
            reserved1: Default::default(),
            reserved2: Default::default(),
            qe_vendor_id: Default::default(), // Could use Uuid crate
            user_data: Default::default(),
        };
        let body = QuoteBody {
            tdx_version: TDXVersion::One,
            tee_tcb_svn: Default::default(),
            mrseam: [0; 48],
            mrsignerseam: [0; 48],
            seamattributes: Default::default(),
            tdattributes: Default::default(),
            xfam: Default::default(),
            mrtd: [0; 48],
            mrconfigid: [0; 48],
            mrowner: [0; 48],
            mrownerconfig: [0; 48],
            rtmr0: [0; 48],
            rtmr1: [0; 48],
            rtmr2: [0; 48],
            rtmr3: [0; 48],
            reportdata,
            tee_tcb_svn_2: None,
            mrservicetd: None,
        };
        // TODO serialize header and body to get message to sign
        let message = b"lsdfkj";
        let signature = signing_key.sign(message);

        Quote {
            header,
            body,
            attestation_key: VerifyingKey::from(&signing_key),
            signature,
            certification_data: CertificationData::QeReportCertificationData(Default::default()),
        }
    }
}

/// Type of TEE used
#[derive(Debug, Eq, PartialEq)]
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
#[derive(Debug, Eq, PartialEq)]
pub enum AttestionKeyType {
    ECDSA256WithP256,
    /// Not yet supported by TDX
    ECDSA384WithP384,
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
pub enum CertificationData {
    PckIdPpidPlainCpusvnPcesvn(Vec<u8>),
    PckIdPpidRSA2048CpusvnPcesvn(Vec<u8>),
    PckIdPpidRSA3072CpusvnPcesvn(Vec<u8>),
    PckLeafCert(Vec<u8>),
    PckCertChain(Vec<u8>),
    QeReportCertificationData(Vec<u8>),
    PlatformManifest(Vec<u8>),
}

impl CertificationData {
    pub fn new(certification_data_type: i16, data: Vec<u8>) -> Result<Self, QuoteParseError> {
        match certification_data_type {
            1 => Ok(Self::PckIdPpidPlainCpusvnPcesvn(data)),
            2 => Ok(Self::PckIdPpidRSA2048CpusvnPcesvn(data)),
            3 => Ok(Self::PckIdPpidRSA3072CpusvnPcesvn(data)),
            4 => Ok(Self::PckLeafCert(data)),
            5 => Ok(Self::PckCertChain(data)),
            6 => Ok(Self::QeReportCertificationData(data)),
            7 => Ok(Self::PlatformManifest(data)),
            _ => Err(QuoteParseError::UnknownCertificationDataType),
        }
    }
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
    return Ok((input, body));
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
