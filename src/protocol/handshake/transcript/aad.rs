const HEADER: &[u8] = b"qsh v1 confirm"; // 14 bytes
const SEP: u8 = 0x00;

pub enum ConfirmRole {
    ClientSends,
    ServerSends,
}

/// Construct AAD for confirm tag AEAD.
#[must_use]
pub fn confirm_aad(transcript_hash: &[u8; 48], role: ConfirmRole) -> Vec<u8> {
    let cap = HEADER.len() + 1 + 48 + 1 + 1;
    let mut aad = Vec::with_capacity(cap);
    aad.extend_from_slice(HEADER);
    aad.push(SEP);
    aad.extend_from_slice(transcript_hash);
    aad.push(SEP);
    aad.push(match role {
        ConfirmRole::ClientSends => 0x01,
        ConfirmRole::ServerSends => 0x02,
    });
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_and_server_aad_differ() {
        let th = [0u8; 48];
        let a_client = confirm_aad(&th, ConfirmRole::ClientSends);
        let a_server = confirm_aad(&th, ConfirmRole::ServerSends);
        assert_ne!(a_client, a_server, "client/server AAD must differ");
        // header is HEADER.len() + 1 + 48 + 1, trailing byte is the role
        let hlen = HEADER.len();
        assert_eq!(&a_client[0..hlen], HEADER);
        assert_eq!(a_client[hlen], SEP);
        assert_eq!(&a_client[(hlen + 1)..(hlen + 1 + 48)], &th);
        assert_eq!(a_client[hlen + 1 + 48], SEP);
        assert_eq!(a_client[hlen + 1 + 48 + 1], 0x01);
        assert_eq!(&a_server[(hlen + 1)..(hlen + 1 + 48)], &th);
        assert_eq!(a_server[hlen + 1 + 48], SEP);
        assert_eq!(a_server[hlen + 1 + 48 + 1], 0x02);
    }

    #[test]
    fn aad_includes_transcript_hash() {
        let th1 = [0u8; 48];
        let th2 = {
            let mut t2 = [0u8; 48];
            t2[0] = 0x01;
            t2
        };
        let a1 = confirm_aad(&th1, ConfirmRole::ClientSends);
        let a2 = confirm_aad(&th2, ConfirmRole::ClientSends);
        assert_ne!(
            a1, a2,
            "different transcript hashes must yield different AAD"
        );
    }
}
