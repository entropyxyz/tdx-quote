use std::io::Read;
use tdx_quote::{Quote, QuoteParseError, VerifyingKey};

#[test]
fn test_parse() {
    let mut file = std::fs::File::open("tests/another_quote.dat").unwrap();
    let mut input = Vec::new();
    file.read_to_end(&mut input).unwrap();
    let quote = Quote::from_bytes(&input).unwrap();
    assert_eq!(quote.header.version, 4);
    // println!("{:?}", quote);

    let pck = [
        4, 166, 103, 136, 58, 157, 155, 124, 186, 75, 81, 133, 87, 255, 233, 182, 192, 125, 235,
        230, 121, 173, 147, 108, 47, 190, 240, 181, 75, 181, 31, 148, 128, 225, 192, 192, 71, 237,
        28, 180, 75, 161, 36, 115, 159, 76, 117, 226, 46, 114, 91, 196, 239, 248, 64, 168, 25, 255,
        101, 241, 162, 113, 245, 253, 148,
    ];
    // if pck is only 64 bytes, add the flag
    // let pck = [&[4], &pck[..]].concat(); // 0x04 means uncompressed
    let pck = VerifyingKey::from_sec1_bytes(&pck).unwrap();
    quote.verify_with_pck(pck).unwrap();

    // Fails to verify signature if the input data changes
    input[49] += 1;
    assert_eq!(
        Quote::from_bytes(&input),
        Err(QuoteParseError::Verification)
    );
}

#[cfg(feature = "mock")]
#[test]
fn test_create_mock_quote() {
    use rand_core::OsRng;
    use tdx_quote::VerifyingKey;
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let quote = Quote::mock(signing_key.clone(), [0; 64]);
    assert_eq!(quote.attestation_key, VerifyingKey::from(signing_key));
    let quote_bytes = quote.as_bytes();
    let quote_deserialized = Quote::from_bytes(&quote_bytes).unwrap();
    assert_eq!(quote, quote_deserialized);
}
