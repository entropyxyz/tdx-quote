#![cfg(feature = "mock")]

use crate::{
    AttestionKeyType, CertificationData, Quote, QuoteBody, QuoteHeader, TDXVersion, TEEType,
    QUOTE_HEADER_LENGTH, V4_QUOTE_BODY_LENGTH,
};
use p256::ecdsa::{signature::SignerMut, SigningKey, VerifyingKey};

impl Quote {
    #[cfg(feature = "mock")]
    /// Create a mock quote
    pub fn mock(mut signing_key: SigningKey, reportdata: [u8; 64]) -> Self {
        let header = QuoteHeader {
            version: 4,
            attestation_key_type: AttestionKeyType::ECDSA256WithP256,
            tee_type: TEEType::TDX,
            reserved1: Default::default(),
            reserved2: Default::default(),
            qe_vendor_id: Default::default(), // Could use Uuid crate
            user_data: Default::default(),
        };
        let body = QuoteBody {
            tdx_version: TDXVersion::One,
            tee_tcb_svn: Default::default(),
            mrseam: [0; 48],
            mrsignerseam: [0; 48],
            seamattributes: Default::default(),
            tdattributes: Default::default(),
            xfam: Default::default(),
            mrtd: [0; 48],
            mrconfigid: [0; 48],
            mrowner: [0; 48],
            mrownerconfig: [0; 48],
            rtmr0: [0; 48],
            rtmr1: [0; 48],
            rtmr2: [0; 48],
            rtmr3: [0; 48],
            reportdata,
            tee_tcb_svn_2: None,
            mrservicetd: None,
        };
        // Serialize header and body to get message to sign
        let mut message = [0; QUOTE_HEADER_LENGTH + V4_QUOTE_BODY_LENGTH];
        message[..QUOTE_HEADER_LENGTH].copy_from_slice(&quote_header_serializer(&header));
        message[QUOTE_HEADER_LENGTH..].copy_from_slice(&quote_body_v4_serializer(&body));
        let signature = signing_key.sign(&message);

        Quote {
            header,
            body,
            attestation_key: VerifyingKey::from(&signing_key),
            signature,
            certification_data: CertificationData::QeReportCertificationData(Default::default()),
        }
    }
}

/// Serialize a quote header, in order to get the data to sign for a mock quote
fn quote_header_serializer(input: &QuoteHeader) -> [u8; QUOTE_HEADER_LENGTH] {
    let mut output = [1; QUOTE_HEADER_LENGTH];
    let version = input.version.to_le_bytes();
    output[..2].copy_from_slice(&version);

    let attestation_key_type = input.attestation_key_type.clone() as u16;
    let attestation_key_type = attestation_key_type.to_le_bytes();
    output[2..4].copy_from_slice(&attestation_key_type);

    let tee_type = input.tee_type.clone() as u32;
    let tee_type = tee_type.to_le_bytes();
    output[4..8].copy_from_slice(&tee_type);

    output[8..10].copy_from_slice(&input.reserved1);
    output[10..12].copy_from_slice(&input.reserved2);
    output[12..28].copy_from_slice(&input.qe_vendor_id);
    output[28..48].copy_from_slice(&input.user_data);

    output
}

/// Serialize a v4 quote body, in order to get the data to sign for a mock quote
fn quote_body_v4_serializer(input: &QuoteBody) -> [u8; V4_QUOTE_BODY_LENGTH] {
    let mut output = [1; V4_QUOTE_BODY_LENGTH];
    output[..16].copy_from_slice(&input.tee_tcb_svn);
    output[16..64].copy_from_slice(&input.mrseam);
    output[64..112].copy_from_slice(&input.mrsignerseam);
    output[112..120].copy_from_slice(&input.seamattributes);
    output[120..128].copy_from_slice(&input.tdattributes);
    output[128..136].copy_from_slice(&input.xfam);
    output[136..184].copy_from_slice(&input.mrtd);
    output[184..232].copy_from_slice(&input.mrconfigid);
    output[232..280].copy_from_slice(&input.mrowner);
    output[280..328].copy_from_slice(&input.mrownerconfig);
    output[328..376].copy_from_slice(&input.rtmr0);
    output[376..424].copy_from_slice(&input.rtmr1);
    output[424..472].copy_from_slice(&input.rtmr2);
    output[472..520].copy_from_slice(&input.rtmr3);
    output[520..].copy_from_slice(&input.reportdata);
    output
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::Quote;
    use std::{io::Read, vec::Vec};
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
}
