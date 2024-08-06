use nom::{
    bytes::complete::take,
    combinator::{map, map_res},
    number::complete::{le_u16, le_u32},
    sequence::tuple,
    IResult,
};

#[derive(Debug)]
pub enum TEEType {
    SGX = 0x00000000,
    TDX = 0x00000081,
}

#[derive(Debug)]
pub struct QuoteHeader {
    pub version: u16,
    pub attestation_key_type: u16,
    pub tee_type: TEEType,
    pub reserved1: [u8; 2],
    pub reserved2: [u8; 2],
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

#[derive(Debug)]
pub struct TDQuoteBodyV4 {
    pub tee_tcb_svn: [u8; 16],
    pub mrseam: [u8; 48],
    pub mrsignerseam: [u8; 48],
    pub seamattributes: [u8; 8],
    pub tdattributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mrtd: [u8; 48],
    pub mrconfigid: [u8; 48],
    pub mrowner: [u8; 48],
    pub mrownerconfig: [u8; 48],
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
    pub reportdata: [u8; 64],
}

/// This is the same as the v4 body but with 2 extra fields
#[derive(Debug)]
pub struct TDQuoteBodyV5Inner {
    pub td_quote_body_v4: TDQuoteBodyV4,
    pub tee_tcb_svn_2: [u8; 16],
    pub mrservicetd: [u8; 48],
}

fn take2(input: &[u8]) -> IResult<&[u8], [u8; 2]> {
    map_res(take(2u8), |i: &[u8]| i.try_into())(input)
}

fn quote_header_parser(input: &[u8]) -> IResult<&[u8], QuoteHeader> {
    map(
        tuple((
            le_u16,
            le_u16,
            take(4u8),
            take2,
            take2,
            take(16u8),
            take(20u8),
        )),
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
            tee_type: TEEType::TDX,
            reserved1,
            reserved2,
            qe_vendor_id: [0u8; 16], // can use Uuid
            user_data: [0u8; 20],
        },
    )(input)
}

fn td_quote_body_v4_parser(input: &[u8]) -> IResult<&[u8], TDQuoteBodyV4> {
    // TODO
    Ok((
        input,
        TDQuoteBodyV4 {
            tee_tcb_svn: [0u8; 16],
            mrseam: [0u8; 48],
            mrsignerseam: [0u8; 48],
            seamattributes: [0u8; 8],
            tdattributes: [0u8; 8],
            xfam: [0u8; 8],
            mrtd: [0u8; 48],
            mrconfigid: [0u8; 48],
            mrowner: [0u8; 48],
            mrownerconfig: [0u8; 48],
            rtmr0: [0u8; 48],
            rtmr1: [0u8; 48],
            rtmr2: [0u8; 48],
            rtmr3: [0u8; 48],
            reportdata: [0u8; 64],
        },
    ))
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
