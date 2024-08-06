use nom::{bytes::complete::take, combinator::map_res, IResult};

// TODO make generic

/// Parser for a [u8; 2]
pub fn take2(input: &[u8]) -> IResult<&[u8], [u8; 2]> {
    map_res(take(2u8), |i: &[u8]| i.try_into())(input)
}

/// Parser for a [u8; 4]
pub fn take4(input: &[u8]) -> IResult<&[u8], [u8; 4]> {
    map_res(take(4u8), |i: &[u8]| i.try_into())(input)
}

/// Parser for a [u8; 8]
pub fn take8(input: &[u8]) -> IResult<&[u8], [u8; 8]> {
    map_res(take(8u8), |i: &[u8]| i.try_into())(input)
}

/// Parser for a [u8; 16]
pub fn take16(input: &[u8]) -> IResult<&[u8], [u8; 16]> {
    map_res(take(16u8), |i: &[u8]| i.try_into())(input)
}

/// Parser for a [u8; 20]
pub fn take20(input: &[u8]) -> IResult<&[u8], [u8; 20]> {
    map_res(take(20u8), |i: &[u8]| i.try_into())(input)
}

/// Parser for a [u8; 48]
pub fn take48(input: &[u8]) -> IResult<&[u8], [u8; 48]> {
    map_res(take(48u8), |i: &[u8]| i.try_into())(input)
}

/// Parser for a [u8; 64]
pub fn take64(input: &[u8]) -> IResult<&[u8], [u8; 64]> {
    map_res(take(64u8), |i: &[u8]| i.try_into())(input)
}
