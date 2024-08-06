use std::io::Read;
use tdx_quote::quote_parser;

#[test]
fn test_parse() {
    let mut file = std::fs::File::open("tests/v4_quote.dat").unwrap();
    let mut input = Vec::new();
    file.read_to_end(&mut input).unwrap();
    let (output, quote) = quote_parser(&input).unwrap();
    println!("unparsed output {:?}", output);
    assert_eq!(quote.header.version, 4);
    print!("{:?}", quote);
}
