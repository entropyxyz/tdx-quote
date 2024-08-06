use nom::{
    bytes::complete::take,
    combinator::map,
    number::complete::{le_u16, le_u32},
    sequence::tuple,
    IResult,
};

mod take;

use take::{take16, take2, take20, take4, take48, take64, take8};

#[derive(Debug)]
pub enum TEEType {
    SGX = 0x00000000,
    TDX = 0x00000081,
}

// TODO impl From<[u8; 4]> for TEEType

#[derive(Debug)]
pub struct QuoteHeader {
    /// Quote version (4 or 5)
    pub version: u16,
    /// Type of the Attestation Key used by the Quoting Enclave. Supported values:
    /// 2 ECDSA-256-with-P-256 curve
    /// 3 ECDSA-384-with-P-384 curve (currently not supported)
    pub attestation_key_type: u16,
    pub tee_type: TEEType,
    /// Currently unused
    pub reserved1: [u8; 2],
    /// Currently unused
    pub reserved2: [u8; 2],
    /// UUID for the quoting enclave vendor
    pub qe_vendor_id: [u8; 16], // can use Uuid
    pub user_data: [u8; 20],
}

#[derive(Debug)]
pub struct Quote {
    pub header: QuoteHeader,
    pub td_quote_body: TDQuoteBody,
    // TODO signature
}

#[derive(Debug)]
pub enum TDQuoteBody {
    V4(TDQuoteBodyV4),
    V5 {
        td_quote_body_type: u16,
        size: u32,
        td_quote_body: TDQuoteBodyV5Inner,
    },
}

/// The main part of the body v4 (v5 also includes all these fields)
#[derive(Debug)]
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

/// This is the same as the v4 body but with 2 extra fields
#[derive(Debug)]
pub struct TDQuoteBodyV5Inner {
    pub td_quote_body_v4: TDQuoteBodyV4,
    pub tee_tcb_svn_2: [u8; 16],
    pub mrservicetd: [u8; 48],
}

/// Parser for a quote header
fn quote_header_parser(input: &[u8]) -> IResult<&[u8], QuoteHeader> {
    map(
        tuple((le_u16, le_u16, take4, take2, take2, take16, take20)),
        |(
            version,
            attestation_key_type,
            tee_type,
            reserved1,
            reserved2,
            qe_vendor_id,
            user_data,
        )| QuoteHeader {
            version,
            attestation_key_type,
            tee_type: TEEType::TDX, // TODO
            reserved1,
            reserved2,
            qe_vendor_id, // can use Uuid
            user_data,
        },
    )(input)
}

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

fn td_quote_body_v5_inner_parser(input: &[u8]) -> IResult<&[u8], TDQuoteBodyV5Inner> {
    let (input, td_quote_body_v4) = td_quote_body_v4_parser(&input)?;
    // take16
    // take48
    Ok((
        input,
        TDQuoteBodyV5Inner {
            td_quote_body_v4,
            tee_tcb_svn_2: [0u8; 16], // TODO
            mrservicetd: [0u8; 48],   // TODO
        },
    ))
}

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

pub fn quote_parser(input: &[u8]) -> IResult<&[u8], Quote> {
    let (input, header) = quote_header_parser(input)?;
    let (input, td_quote_body) = td_body_parser(input, header.version)?;
    Ok((
        input,
        Quote {
            header,
            td_quote_body,
        },
    ))
}
