#![no_std]

extern crate alloc;
use alloc::vec::Vec;

use nom::{
    bytes::complete::take,
    combinator::{map, map_res},
    number::complete::{le_i16, le_i32, le_u16, le_u32},
    sequence::tuple,
    IResult,
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

mod take_n;

use take_n::{take16, take2, take20, take48, take64, take8};

/// Type of TEE used
#[derive(Debug)]
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
#[derive(Debug)]
pub enum AttestionKeyType {
    ECDSA256WithP256,
    ECDSA384WithP384, // Not yet supported by TDX
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
#[derive(Debug)]
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

/// A TDX Quote
#[derive(Debug)]
pub struct Quote {
    pub header: QuoteHeader,
    pub td_quote_body: TDQuoteBody,
    pub signature: Signature,
    pub attestation_key: VerifyingKey,
    pub certification_data: CertificationData,
}

impl Quote {
    fn body_v4(&self) -> TDQuoteBodyV4 {
        // TODO do this without cloning
        match self.td_quote_body.clone() {
            TDQuoteBody::V4(body_v4) => body_v4,
            TDQuoteBody::V5 { td_quote_body, .. } => td_quote_body.td_quote_body_v4,
        }
    }

    /// Returns the report data
    pub fn report_input_data(&self) -> [u8; 64] {
        self.body_v4().reportdata
    }

    /// Returns the build-time measurement register
    pub fn mrtd(&self) -> [u8; 48] {
        self.body_v4().mrtd
    }
}

#[derive(Debug, Clone)]
pub enum TDQuoteBody {
    V4(TDQuoteBodyV4),
    V5 {
        td_quote_body_type: u16,
        size: u32,
        td_quote_body: TDQuoteBodyV5Inner,
    },
}

/// The main part of the body v4 (v5 also includes all these fields)
#[derive(Debug, Clone)]
pub struct TDQuoteBodyV4 {
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
}

/// A v5 quote body - which is the same as the v4 body but with 2 extra fields
#[derive(Debug, Clone)]
pub struct TDQuoteBodyV5Inner {
    pub td_quote_body_v4: TDQuoteBodyV4,
    pub tee_tcb_svn_2: [u8; 16],
    pub mrservicetd: [u8; 48],
}

/// Data required to verify the QE Report Signature
#[non_exhaustive]
#[derive(Debug)]
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
    pub fn new(certification_data_type: i16, data: Vec<u8>) -> Result<Self, nom::Err<i16>> {
        match certification_data_type {
            1 => Ok(Self::PckIdPpidPlainCpusvnPcesvn(data)),
            2 => Ok(Self::PckIdPpidRSA2048CpusvnPcesvn(data)),
            3 => Ok(Self::PckIdPpidRSA3072CpusvnPcesvn(data)),
            4 => Ok(Self::PckLeafCert(data)),
            5 => Ok(Self::PckCertChain(data)),
            6 => Ok(Self::QeReportCertificationData(data)),
            7 => Ok(Self::PlatformManifest(data)),
            _ => Err(nom::Err::Failure(certification_data_type)),
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
                qe_vendor_id, // can use Uuid
                user_data,
            })
        },
    )(input)
}

/// Parser for a v4 quote body
fn td_quote_body_v4_parser(input: &[u8]) -> IResult<&[u8], TDQuoteBodyV4> {
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
        )| TDQuoteBodyV4 {
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
        },
    )(input)
}

/// Parser for a v5 quote body
fn td_quote_body_v5_inner_parser(input: &[u8]) -> IResult<&[u8], TDQuoteBodyV5Inner> {
    map(
        tuple((td_quote_body_v4_parser, take16, take48)),
        |(td_quote_body_v4, tee_tcb_svn_2, mrservicetd)| TDQuoteBodyV5Inner {
            td_quote_body_v4,
            tee_tcb_svn_2,
            mrservicetd,
        },
    )(input)
}

/// Parse for a quote body
fn td_body_parser(input: &[u8], version: u16) -> IResult<&[u8], TDQuoteBody> {
    match version {
        4 => {
            let (input, td_quote_body) = td_quote_body_v4_parser(&input)?;
            Ok((input, TDQuoteBody::V4(td_quote_body)))
        }
        5 => map(
            tuple((le_u16, le_u32, td_quote_body_v5_inner_parser)),
            |(td_quote_body_type, size, td_quote_body)| TDQuoteBody::V5 {
                td_quote_body_type,
                size,
                td_quote_body,
            },
        )(input),
        _ => Err(nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Fail,
        ))),
    }
}

/// Parse a TDX quote
pub fn quote_parser(input: &[u8]) -> IResult<&[u8], Quote> {
    let original_input = input;
    let (input, header) = quote_header_parser(input)?;
    let body_length = match header.version {
        4 => 584,
        5 => 584 + 64,
        _ => 0, // TODO
    };
    let signed_data = &original_input[..48 + body_length];
    let (input, td_quote_body) = td_body_parser(input, header.version)?;

    // Signature
    let (input, _signature_section_length) = le_i32(input)?;
    let (input, signature) = take(64u8)(input)?;
    let signature = Signature::from_bytes(signature.into()).map_err(|_| {
        nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Fail))
    })?;

    // Attestation key
    let (input, attestation_key) = take(64u8)(input)?;
    let attestation_key = [&[04], attestation_key].concat(); // 0x04 means uncompressed
    let attestation_key = VerifyingKey::from_sec1_bytes(&attestation_key).map_err(|_| {
        nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Fail))
    })?;

    // Verify signature
    attestation_key
        .verify(signed_data, &signature)
        .map_err(|_| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Fail))
        })?;

    // Certification data
    let (input, certification_data_type) = le_i16(input)?;
    let (input, certification_dat_len) = le_i32(input)?;
    let certification_dat_len: usize = certification_dat_len.try_into().map_err(|_| {
        nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Fail))
    })?;
    let (input, certification_data) = take(certification_dat_len)(input)?;
    let certification_data =
        CertificationData::new(certification_data_type, certification_data.to_vec()).map_err(
            |_| nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Fail)),
        )?;

    Ok((
        input,
        Quote {
            header,
            td_quote_body,
            signature,
            attestation_key,
            certification_data,
        },
    ))
}
