use std::io::Read;
use tdx_quote::{Quote, QuoteParseError};

#[test]
fn test_parse() {
    let mut file = std::fs::File::open("tests/v4_quote.dat").unwrap();
    let mut input = Vec::new();
    file.read_to_end(&mut input).unwrap();
    let quote = Quote::from_bytes(&input).unwrap();
    assert_eq!(quote.header.version, 4);
    print!("{:?}", quote);

    // Fails to verify signature if the input data changes
    input[49] += 1;
    assert_eq!(
        Quote::from_bytes(&input),
        Err(QuoteParseError::Verification)
    );
}
