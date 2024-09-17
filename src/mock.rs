#![cfg(feature = "mock")]

use crate::{
    AttestionKeyType, CertificationData, QeReportCertificationData, Quote, QuoteBody, QuoteHeader,
    TDXVersion, TEEType, QUOTE_HEADER_LENGTH, V4_QUOTE_BODY_LENGTH,
};
use alloc::vec::Vec;
use p256::ecdsa::{signature::SignerMut, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const V4_MOCK_QUOTE_LENGTH: usize =
    QUOTE_HEADER_LENGTH + V4_QUOTE_BODY_LENGTH + 4 + 64 + 64 + 2 + 4;

impl Quote {
    #[cfg(feature = "mock")]
    /// Create a mock quote
    pub fn mock(
        mut attestation_key: SigningKey,
        mut provisioning_certification_key: SigningKey,
        reportdata: [u8; 64],
    ) -> Self {
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
        let signature = attestation_key.sign(&message);

        let verifying_key = attestation_key.verifying_key().to_sec1_bytes();
        // Create a mock qe_report_cerification_data
        let qe_authentication_data = Default::default();
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(&verifying_key[1..]);
            hasher.update(&qe_authentication_data);
            hasher.finalize()
        };
        let mut qe_report = [0u8; 384];
        {
            let (_left, right) = qe_report.split_at_mut(384 - 64);
            right[..32].copy_from_slice(&hash);
        }
        let qe_report_cerification_data = QeReportCertificationData {
            qe_report,
            signature: provisioning_certification_key.sign(&qe_report),
            qe_authentication_data,
            certification_data: Default::default(),
        };

        Quote {
            header,
            body,
            attestation_key: VerifyingKey::from(&attestation_key),
            signature,
            certification_data: CertificationData::QeReportCertificationData(
                qe_report_cerification_data,
            ),
        }
    }

    pub fn as_bytes(&self) -> [u8; V4_MOCK_QUOTE_LENGTH + 384 + 64 + 2] {
        let mut output = [1; V4_MOCK_QUOTE_LENGTH + 384 + 64 + 2];
        let header = quote_header_serializer(&self.header);
        output[..48].copy_from_slice(&header);

        let body = quote_body_v4_serializer(&self.body);
        output[48..632].copy_from_slice(&body);

        // TODO get actual signature section length
        let signature_section_length = 0i32;
        let signature_section_length = signature_section_length.to_le_bytes();
        output[632..636].copy_from_slice(&signature_section_length);

        let signature = self.signature.to_bytes();
        output[636..700].copy_from_slice(&signature);

        let attestation_key = self.attestation_key.to_sec1_bytes();
        // remove 0x04 prefix
        output[700..764].copy_from_slice(&attestation_key[1..]);

        // Certification data type
        let certification_data_type: i16 = 6;
        let certification_data_type = certification_data_type.to_le_bytes();
        output[764..766].copy_from_slice(&certification_data_type);

        let certification_data = certification_data_serializer(&self.certification_data);
        let certification_data_len: i32 = certification_data.len().try_into().unwrap();
        let certification_data_len = certification_data_len.to_le_bytes();
        output[766..770].copy_from_slice(&certification_data_len);

        output[770..].copy_from_slice(&certification_data);
        output
    }
}

fn certification_data_serializer(input: &CertificationData) -> Vec<u8> {
    let mut output = [0u8; 384 + 64 + 2];
    match input {
        CertificationData::QeReportCertificationData(qe_report_certification_data) => {
            output[..384].copy_from_slice(&qe_report_certification_data.qe_report);
            let signature = qe_report_certification_data.signature.to_bytes();
            output[384..384 + 64].copy_from_slice(&signature);

            let qe_authentication_data_length = 0i16;
            let qe_authentication_data_length = qe_authentication_data_length.to_le_bytes();
            output[384 + 64..384 + 64 + 2].copy_from_slice(&qe_authentication_data_length);
            // output[384 + 64..].copy_from_slice(qe_report_cerification_data.qe_authentication_data);
        }
        _ => todo!(),
    }
    output.to_vec()
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

    #[test]
    fn test_serialize_header() {
        let mut file = std::fs::File::open("tests/test-quotes/v4_quote.dat").unwrap();
        let mut input = Vec::new();
        file.read_to_end(&mut input).unwrap();
        let quote = Quote::from_bytes(&input).unwrap();
        let serialized = quote_header_serializer(&quote.header);
        assert_eq!(serialized, input[..48]);
    }

    #[test]
    fn test_serialize_body() {
        let mut file = std::fs::File::open("tests/test-quotes/v4_quote.dat").unwrap();
        let mut input = Vec::new();
        file.read_to_end(&mut input).unwrap();
        let quote = Quote::from_bytes(&input).unwrap();
        let serialized = quote_body_v4_serializer(&quote.body);
        assert_eq!(serialized, input[48..48 + 584]);
    }
}
