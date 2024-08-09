use std::io::Read;
use tdx_quote::{quote_body_v4_serializer, quote_header_serializer, Quote, QuoteParseError};

#[test]
fn test_parse() {
    let mut file = std::fs::File::open("tests/v4_quote.dat").unwrap();
    let mut input = Vec::new();
    file.read_to_end(&mut input).unwrap();
    let quote = Quote::from_bytes(&input).unwrap();
    assert_eq!(quote.header.version, 4);
    println!("{:?}", quote);

    // Fails to verify signature if the input data changes
    input[49] += 1;
    assert_eq!(
        Quote::from_bytes(&input),
        Err(QuoteParseError::Verification)
    );
}

// TODO this should be a unit test for private fn
#[test]
fn test_serialize_header() {
    let mut file = std::fs::File::open("tests/v4_quote.dat").unwrap();
    let mut input = Vec::new();
    file.read_to_end(&mut input).unwrap();
    let quote = Quote::from_bytes(&input).unwrap();
    let serialized = quote_header_serializer(&quote.header);
    assert_eq!(serialized, input[..48]);
}

// TODO this should be a unit test for private fn
#[test]
fn test_serialize_body() {
    let mut file = std::fs::File::open("tests/v4_quote.dat").unwrap();
    let mut input = Vec::new();
    file.read_to_end(&mut input).unwrap();
    let quote = Quote::from_bytes(&input).unwrap();
    let serialized = quote_body_v4_serializer(&quote.body);
    assert_eq!(serialized, input[48..48 + 584]);
}

#[test]
fn test_create_mock_quote() {
    use rand_core::OsRng;
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let _quote = Quote::mock(signing_key, [0; 64]);
}
