use crate::application::handshake::TranscriptPort;

pub struct Sha384Transcript {
    h: [u8; 48],
}

impl TranscriptPort for Sha384Transcript {
    /// Absorb bytes into the transcript hash.
    /// This uses SHA-384 in a simple sponge-like construction.
    /// It is not a general-purpose hash function.
    /// It is only suitable for absorbing handshake messages in a canonical form.
    fn absorb_canonical(&mut self, bytes: &[u8]) {
        use sha2::{Digest, Sha384};
        let mut hasher = Sha384::new();
        hasher.update(self.h);
        hasher.update(bytes);
        self.h.copy_from_slice(&hasher.finalize());
    }

    /// Return the current transcript hash.
    fn hash(&self) -> [u8; 48] {
        self.h
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::handshake::TranscriptPort;
    use sha2::{Digest, Sha384};

    // Helper to create a fresh transcript with zero state.
    fn new_tx() -> Sha384Transcript {
        Sha384Transcript { h: [0u8; 48] }
    }

    #[test]
    fn empty_transcript_hash_is_sha384_of_zero_block() {
        // Reproduce expected starting hash after zero absorb steps:
        // Implementation defines initial h = 48 zero bytes (not the SHA-384 IV). That is a design choice.
        let tx = new_tx();
        assert_eq!(tx.hash(), [0u8; 48]);
    }

    #[test]
    fn single_absorb_matches_manual_update() {
        let mut tx = new_tx();
        let data = b"HELLO";
        // Manual reproduction: SHA384( h || data ) with h = zeros
        let mut hasher = Sha384::new();
        hasher.update([0u8; 48]);
        hasher.update(data);
        let expect: [u8; 48] = hasher.finalize().into();
        tx.absorb_canonical(data);
        assert_eq!(tx.hash(), expect);
    }

    #[test]
    fn two_step_absorb_differs_from_concatenated_once() {
        let mut tx_seq = new_tx();
        tx_seq.absorb_canonical(b"ACCEPT");
        tx_seq.absorb_canonical(b"FINISH");
        let seq_hash = tx_seq.hash();

        // One-shot manual: h0=0s; SHA384( SHA384(0||ACCEPT) || FINISH ) vs SHA384( 0 || ACCEPT||FINISH )
        let mut h_first = Sha384::new();
        h_first.update([0u8; 48]);
        h_first.update(b"ACCEPT");
        let mid: [u8; 48] = h_first.finalize().into();
        let mut h_chained = Sha384::new();
        h_chained.update(mid);
        h_chained.update(b"FINISH");
        let chained: [u8; 48] = h_chained.finalize().into();
        assert_eq!(
            seq_hash, chained,
            "sequential absorb must emulate chaining model"
        );

        let mut h_concat = Sha384::new();
        h_concat.update([0u8; 48]);
        h_concat.update(b"ACCEPTFINISH");
        let concat: [u8; 48] = h_concat.finalize().into();
        assert_ne!(
            seq_hash, concat,
            "two-step sponge differs from direct concatenation hash"
        );
    }

    #[test]
    fn order_sensitivity() {
        let mut tx1 = new_tx();
        let mut tx2 = new_tx();
        tx1.absorb_canonical(b"A");
        tx1.absorb_canonical(b"B");
        tx2.absorb_canonical(b"B");
        tx2.absorb_canonical(b"A");
        assert_ne!(tx1.hash(), tx2.hash(), "order must affect transcript hash");
    }

    #[test]
    fn distinct_inputs_change_hash() {
        let mut tx = new_tx();
        let base = tx.hash();
        tx.absorb_canonical(b"X");
        assert_ne!(tx.hash(), base, "absorbing data must change hash state");
    }
}
