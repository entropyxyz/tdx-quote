use std::{fs, io::Read};
use tdx_quote::{Quote, QuoteParseError, VerifyingKey};

/// The PCK used for some of the test quotes
const KNOWN_PCK: [u8; 65] = [
    4, 166, 103, 136, 58, 157, 155, 124, 186, 75, 81, 133, 87, 255, 233, 182, 192, 125, 235, 230,
    121, 173, 147, 108, 47, 190, 240, 181, 75, 181, 31, 148, 128, 225, 192, 192, 71, 237, 28, 180,
    75, 161, 36, 115, 159, 76, 117, 226, 46, 114, 91, 196, 239, 248, 64, 168, 25, 255, 101, 241,
    162, 113, 245, 253, 148,
];

#[test]
fn test_parse() {
    for entry in fs::read_dir("tests/test-quotes").unwrap() {
        let entry = entry.unwrap();
        let mut file = fs::File::open(entry.path()).unwrap();
        let mut input = Vec::new();
        file.read_to_end(&mut input).unwrap();
        let quote = Quote::from_bytes(&input).unwrap();

        // We currently don't have any v5 quotes to test with
        assert_eq!(quote.header.version, 4);

        // We have one quote for which the PCK is unknown, but we still want to test that it parses
        if entry.file_name().to_str().unwrap().starts_with("known_pck") {
            let pck = VerifyingKey::from_sec1_bytes(&KNOWN_PCK).unwrap();
            quote.verify_with_pck(pck).unwrap();
        }

        // Fails to verify signature if the input data changes
        input[49] += 1;
        assert_eq!(
            Quote::from_bytes(&input),
            Err(QuoteParseError::Verification)
        );
    }
}

#[cfg(feature = "mock")]
#[test]
fn test_create_mock_quote() {
    use rand_core::OsRng;
    use tdx_quote::VerifyingKey;
    let attestation_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let provisioning_certification_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let quote = Quote::mock(
        attestation_key.clone(),
        provisioning_certification_key.clone(),
        [0; 64],
    );
    assert_eq!(quote.attestation_key, VerifyingKey::from(attestation_key));
    quote
        .verify_with_pck(VerifyingKey::from(provisioning_certification_key))
        .unwrap();
    let quote_bytes = quote.as_bytes();
    let quote_deserialized = Quote::from_bytes(&quote_bytes).unwrap();
    assert_eq!(quote, quote_deserialized);
}
