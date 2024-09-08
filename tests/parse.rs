use std::io::Read;
use tdx_quote::{Quote, QuoteParseError, Verifier, VerifyingKey};

#[test]
fn test_parse() {
    let mut file = std::fs::File::open("tests/another_quote.dat").unwrap();
    let mut input = Vec::new();
    file.read_to_end(&mut input).unwrap();
    let quote = Quote::from_bytes(&input).unwrap();
    assert_eq!(quote.header.version, 4);
    println!("{:?}", quote.certification_data);
    let qe_report_certification_data = quote.qe_report_certification_data().unwrap();

    let attestation_key = [0u8; 64];
    // if attestation key is only 64 bytes, add the flag
    let attestation_key = [&[4], &attestation_key[..]].concat(); // 0x04 means uncompressed
    let attestation_key = VerifyingKey::from_sec1_bytes(&attestation_key).unwrap();
    attestation_key
        .verify(
            &qe_report_certification_data.qe_report[..],
            &qe_report_certification_data.signature,
        )
        .unwrap();

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
