use crate::application::handshake::{
    ApplicationHandshakeError, HandshakeTranscriptRef, HandshakeWire,
};
use crate::domain::handshake::{Accept, FinishClient, FinishServer, Hello};
use crate::ports::crypto::{AEAD_TAG_LEN, AeadSeal, Seq};
use crate::protocol::handshake::keyschedule::{DirectionKeys, WriteKeys, derive_keys, prk_from};
use crate::protocol::handshake::transcript::aad::{ConfirmRole, confirm_aad};

use super::fsm_types::{HandshakeEvent, HandshakeState, KeySink, Role, TranscriptPort};

/// Orchestrates the qsh handshake flow (HELLO → ACCEPT → FINISH*) while
/// maintaining the transcript hash, performing lazy key derivation and
/// verifying / producing confirm tags.
///
/// See `fsm_types::HandshakeState` for the coarse progress milestones. Methods
/// prefixed with `on_` consume inbound messages (verify + absorb) whereas
/// `build_` methods produce outbound messages (seal + absorb).
///
/// Internal helper steps (`encode_absorb`, `derive_keys_and_th`, confirm seal /
/// verify) are intentionally private to keep the external surface minimal.
///
/// Error strategy: all misuse (wrong state, failed cryptographic verification,
/// encoding problems) returns `ApplicationHandshakeError::ValidationError`. No
/// panics occur for expected protocol faults (only a `debug_assert!` prevents
/// state regression in debug builds).
#[derive(Debug, PartialEq, Eq)]
pub struct HandshakeFsm<C: KeySink, T: TranscriptPort, A: AeadSeal, W: HandshakeWire> {
    pub(crate) role: Role,
    pub(crate) state: HandshakeState,
    pub(crate) conn: C,
    pub(crate) transcript: T,
    pub(crate) aead: A,
    pub(crate) wire: W,
    pub(crate) prk: Option<[u8; 48]>,
    pub(crate) writes: Option<WriteKeys>,
    pub(crate) next_cli_write: Seq,
    pub(crate) next_srv_write: Seq,
    pub(crate) next_cli_read: Seq,
    pub(crate) next_srv_read: Seq,
}

impl<C: KeySink, T: TranscriptPort, A: AeadSeal, W: HandshakeWire> HandshakeFsm<C, T, A, W> {
    /// Construct a new `HandshakeFsm` for `role` with provided dependencies.
    ///
    /// Starts in `HandshakeState::Start` with empty transcript and unset PRK.
    pub fn new(role: Role, conn: C, transcript: T, aead: A, wire: W) -> Self {
        Self {
            role,
            state: HandshakeState::Start,
            conn,
            transcript,
            aead,
            wire,
            prk: None,
            writes: None,
            next_cli_write: Seq(0),
            next_srv_write: Seq(0),
            next_cli_read: Seq(0),
            next_srv_read: Seq(0),
        }
    }

    /// Force transition into `HandshakeState::ReadyToComplete`.
    ///
    /// Idempotent convenience used mainly in tests or orchestration glue.
    pub fn ready(&mut self) {
        let _ = self.apply(HandshakeEvent::MarkReady);
    }

    /// Provide the concatenated hybrid shared secret (`x25519_shared || mlkem_shared`).
    ///
    /// Computes and stores the PRK mixing in the current transcript hash.
    pub fn set_hybrid_shared(&mut self, shared: &[u8]) {
        let th = self.transcript.hash();
        self.prk = Some(prk_from(&th, shared));
    }

    fn state_ordinal(state: HandshakeState) -> u8 {
        match state {
            HandshakeState::Start => 0,
            HandshakeState::SentHello | HandshakeState::GotHello => 1,
            HandshakeState::SentAccept | HandshakeState::GotAccept => 2,
            HandshakeState::SentFinishClient | HandshakeState::GotFinishClient => 3,
            HandshakeState::SentFinishServer => 4,
            HandshakeState::ReadyToComplete => 5,
            HandshakeState::Complete => 6,
        }
    }

    fn encode_absorb(
        &mut self,
        r: HandshakeTranscriptRef<'_>,
        label: &str,
    ) -> Result<(), ApplicationHandshakeError> {
        let bytes = self.wire.encode_transcript(r).map_err(|e| {
            ApplicationHandshakeError::ValidationError(format!("wire encode {label} failed: {e}"))
        })?;
        self.transcript.absorb_canonical(&bytes);
        Ok(())
    }

    fn derive_keys_and_th(&mut self) -> Result<([u8; 48], WriteKeys), ApplicationHandshakeError> {
        if self.writes.is_none() {
            let prk = self.prk.ok_or_else(|| {
                ApplicationHandshakeError::ValidationError(
                    "PRK not set (call set_hybrid_shared)".into(),
                )
            })?;
            let th_now = self.transcript.hash();
            let wk_now = derive_keys(&th_now, &prk)?;
            self.writes = Some(wk_now);
        }
        let th = self.transcript.hash();
        let wk = self
            .writes
            .as_ref()
            .ok_or_else(|| ApplicationHandshakeError::ValidationError("writes unavailable".into()))?
            .clone();
        Ok((th, wk))
    }

    fn dir_keys(role: ConfirmRole, wk: &WriteKeys) -> &DirectionKeys {
        match role {
            ConfirmRole::ClientSends => &wk.client,
            ConfirmRole::ServerSends => &wk.server,
        }
    }

    fn seal_confirm(
        aead_impl: &A,
        role: ConfirmRole,
        wk: &WriteKeys,
        seq: &mut Seq,
        aad: &[u8],
    ) -> Result<[u8; AEAD_TAG_LEN], ApplicationHandshakeError> {
        let dk = Self::dir_keys(role, wk);
        let tag = aead_impl
            .seal_detached_tag(&dk.key, dk.salt, *seq, aad)
            .map_err(|_| {
                ApplicationHandshakeError::ValidationError("confirm tag seal failed".into())
            })?;
        seq.0 += 1;
        Ok(tag)
    }

    fn verify_confirm(
        aead_impl: &A,
        role: ConfirmRole,
        wk: &WriteKeys,
        seq: &mut Seq,
        aad: &[u8],
        tag_bytes: &[u8],
    ) -> Result<(), ApplicationHandshakeError> {
        let dk = Self::dir_keys(role, wk);
        let tag = Self::tag_as_array(tag_bytes)?;
        aead_impl
            .open_detached_tag(&dk.key, dk.salt, *seq, aad, &tag)
            .map_err(|_| {
                ApplicationHandshakeError::ValidationError("confirm tag verification failed".into())
            })?;
        seq.0 += 1;
        Ok(())
    }

    fn apply(&mut self, ev: HandshakeEvent) -> Result<(), ApplicationHandshakeError> {
        let old = self.state;
        let role = self.role;
        let new = match (role, old, ev) {
            (Role::Client, HandshakeState::Start, HandshakeEvent::ClientSendHello) => {
                HandshakeState::SentHello
            }
            (Role::Client, HandshakeState::SentHello, HandshakeEvent::ClientRecvAccept) => {
                HandshakeState::GotAccept
            }
            (Role::Client, HandshakeState::GotAccept, HandshakeEvent::ClientSendFinishClient) => {
                HandshakeState::SentFinishClient
            }
            (Role::Server, HandshakeState::Start, HandshakeEvent::ServerRecvHello) => {
                HandshakeState::GotHello
            }
            (Role::Server, HandshakeState::GotHello, HandshakeEvent::ServerSendAccept) => {
                HandshakeState::SentAccept
            }
            (Role::Server, HandshakeState::SentAccept, HandshakeEvent::ServerRecvFinishClient) => {
                HandshakeState::GotFinishClient
            }
            (
                Role::Client,
                HandshakeState::GotAccept | HandshakeState::SentFinishClient,
                HandshakeEvent::ClientRecvFinishServer,
            )
            | (
                Role::Server,
                HandshakeState::GotFinishClient,
                HandshakeEvent::ServerSendFinishServer,
            )
            | (_, HandshakeState::ReadyToComplete, HandshakeEvent::MarkReady) => {
                HandshakeState::ReadyToComplete
            }
            (_, HandshakeState::ReadyToComplete, HandshakeEvent::Complete) => {
                HandshakeState::Complete
            }
            (_, s, HandshakeEvent::MarkReady) if s != HandshakeState::ReadyToComplete => {
                HandshakeState::ReadyToComplete
            }
            _ => {
                return Err(ApplicationHandshakeError::ValidationError(
                    "invalid transition".into(),
                ));
            }
        };
        debug_assert!(
            Self::state_ordinal(new) >= Self::state_ordinal(old),
            "state regression: {old:?} -> {new:?}"
        );
        self.state = new;
        Ok(())
    }

    fn tag_as_array(tag: &[u8]) -> Result<[u8; AEAD_TAG_LEN], ApplicationHandshakeError> {
        if tag.len() != AEAD_TAG_LEN {
            return Err(ApplicationHandshakeError::ValidationError(
                "confirm tag wrong length".into(),
            ));
        }
        let mut arr = [0u8; AEAD_TAG_LEN];
        arr.copy_from_slice(tag);
        Ok(arr)
    }

    // Client side
    /// Client: absorb outbound `HELLO`; transition `Start` → `SentHello`.
    ///
    /// # Errors
    /// Returns `ApplicationHandshakeError::ValidationError` if canonical wire
    /// encoding fails or the state transition is invalid for the current
    /// `HandshakeState` / `Role`.
    pub fn on_start_client_send_hello(
        &mut self,
        hello: &Hello,
    ) -> Result<(), ApplicationHandshakeError> {
        self.encode_absorb(HandshakeTranscriptRef::Hello(hello), "HELLO")?;
        self.apply(HandshakeEvent::ClientSendHello)
    }
    /// Client: absorb inbound `ACCEPT`; transition `SentHello` → `GotAccept`.
    ///
    /// # Errors
    /// Returns `ApplicationHandshakeError::ValidationError` if encoding fails
    /// or the transition is not permitted.
    pub fn on_accept(&mut self, accept: &Accept) -> Result<(), ApplicationHandshakeError> {
        self.encode_absorb(HandshakeTranscriptRef::Accept(accept), "ACCEPT")?;
        self.apply(HandshakeEvent::ClientRecvAccept)
    }
    /// Client: verify server confirm then absorb `FINISH_SERVER`.
    ///
    /// # Errors
    /// - `ApplicationHandshakeError::ValidationError` for wrong state/role.
    /// - Validation error if key derivation or confirm tag verification fails.
    /// - Validation error if wire encoding fails.
    pub fn on_finish_server(
        &mut self,
        finish_server: &FinishServer,
    ) -> Result<(), ApplicationHandshakeError> {
        if self.role != Role::Client
            || !(self.state == HandshakeState::GotAccept
                || self.state == HandshakeState::SentFinishClient)
        {
            return Err(ApplicationHandshakeError::ValidationError(
                "invalid state for FINISH_SERVER".into(),
            ));
        }
        let (th, wk) = self.derive_keys_and_th()?;
        let aad = confirm_aad(&th, ConfirmRole::ServerSends);
        let mut seq_tmp = self.next_srv_read;
        Self::verify_confirm(
            &self.aead,
            ConfirmRole::ServerSends,
            &wk,
            &mut seq_tmp,
            &aad,
            &finish_server.server_confirm,
        )?;
        self.next_srv_read = seq_tmp;
        self.encode_absorb(
            HandshakeTranscriptRef::FinishServer(finish_server),
            "FINISH_SERVER",
        )?;
        self.apply(HandshakeEvent::ClientRecvFinishServer)
    }
    /// Client: build (seal confirm) + absorb `FINISH_CLIENT`.
    ///
    /// # Errors
    /// Returns `ApplicationHandshakeError::ValidationError` for invalid
    /// state/role, confirm sealing failure, key derivation failure or wire
    /// encoding failure.
    pub fn build_finish_client(
        &mut self,
        mut fc: FinishClient,
    ) -> Result<FinishClient, ApplicationHandshakeError> {
        if self.role != Role::Client || self.state != HandshakeState::GotAccept {
            return Err(ApplicationHandshakeError::ValidationError(
                "invalid state for build FINISH_CLIENT".into(),
            ));
        }
        let (th, wk) = self.derive_keys_and_th()?;
        let aad = confirm_aad(&th, ConfirmRole::ClientSends);
        let mut seq_tmp = self.next_cli_write;
        let tag = Self::seal_confirm(
            &self.aead,
            ConfirmRole::ClientSends,
            &wk,
            &mut seq_tmp,
            &aad,
        )?;
        self.next_cli_write = seq_tmp;
        fc.client_confirm = tag.to_vec();
        self.encode_absorb(HandshakeTranscriptRef::FinishClient(&fc), "FINISH_CLIENT")?;
        self.apply(HandshakeEvent::ClientSendFinishClient)?;
        Ok(fc)
    }

    // Server side
    /// Server: absorb inbound `HELLO`; transition `Start` → `GotHello`.
    ///
    /// # Errors
    /// Returns `ApplicationHandshakeError::ValidationError` if encoding fails
    /// or the transition is invalid.
    pub fn on_hello(&mut self, hello: &Hello) -> Result<(), ApplicationHandshakeError> {
        self.encode_absorb(HandshakeTranscriptRef::Hello(hello), "HELLO")?;
        self.apply(HandshakeEvent::ServerRecvHello)
    }
    /// Server: absorb outbound `ACCEPT`; transition `GotHello` → `SentAccept`.
    ///
    /// # Errors
    /// Returns `ApplicationHandshakeError::ValidationError` if encoding fails
    /// or the state does not allow the transition.
    pub fn on_start_server_send_accept(
        &mut self,
        accept: &Accept,
    ) -> Result<(), ApplicationHandshakeError> {
        self.encode_absorb(HandshakeTranscriptRef::Accept(accept), "ACCEPT")?;
        self.apply(HandshakeEvent::ServerSendAccept)
    }
    /// Server: verify client confirm then absorb `FINISH_CLIENT`.
    ///
    /// # Errors
    /// - `ApplicationHandshakeError::ValidationError` for wrong state/role.
    /// - Validation error if key derivation or confirm tag verification fails.
    /// - Validation error if wire encoding fails.
    pub fn on_finish_client(
        &mut self,
        finish_client: &FinishClient,
    ) -> Result<(), ApplicationHandshakeError> {
        if self.role != Role::Server || self.state != HandshakeState::SentAccept {
            return Err(ApplicationHandshakeError::ValidationError(
                "invalid state for FINISH_CLIENT".into(),
            ));
        }
        let (th, wk) = self.derive_keys_and_th()?;
        let aad = confirm_aad(&th, ConfirmRole::ClientSends);
        let mut seq_tmp = self.next_cli_read;
        Self::verify_confirm(
            &self.aead,
            ConfirmRole::ClientSends,
            &wk,
            &mut seq_tmp,
            &aad,
            &finish_client.client_confirm,
        )?;
        self.next_cli_read = seq_tmp;
        self.encode_absorb(
            HandshakeTranscriptRef::FinishClient(finish_client),
            "FINISH_CLIENT",
        )?;
        self.apply(HandshakeEvent::ServerRecvFinishClient)
    }
    /// Server: build (seal confirm) + absorb `FINISH_SERVER`.
    ///
    /// # Errors
    /// Returns `ApplicationHandshakeError::ValidationError` for invalid state,
    /// confirm sealing failure, key derivation failure, or wire encoding failure.
    pub fn build_finish_server(
        &mut self,
        mut fs: FinishServer,
    ) -> Result<FinishServer, ApplicationHandshakeError> {
        if self.role != Role::Server || self.state != HandshakeState::GotFinishClient {
            return Err(ApplicationHandshakeError::ValidationError(
                "invalid state for build FINISH_SERVER".into(),
            ));
        }
        let (th, wk) = self.derive_keys_and_th()?;
        let aad = confirm_aad(&th, ConfirmRole::ServerSends);
        let mut seq_tmp = self.next_srv_write;
        let tag = Self::seal_confirm(
            &self.aead,
            ConfirmRole::ServerSends,
            &wk,
            &mut seq_tmp,
            &aad,
        )?;
        self.next_srv_write = seq_tmp;
        fs.server_confirm = tag.to_vec();
        self.encode_absorb(HandshakeTranscriptRef::FinishServer(&fs), "FINISH_SERVER")?;
        self.apply(HandshakeEvent::ServerSendFinishServer)?;
        Ok(fs)
    }

    // Test shims
    #[cfg(test)]
    pub fn test_client_send_hello(&mut self) -> Result<(), ApplicationHandshakeError> {
        self.apply(HandshakeEvent::ClientSendHello)
    }
    #[cfg(test)]
    pub fn test_client_recv_accept(&mut self) -> Result<(), ApplicationHandshakeError> {
        self.apply(HandshakeEvent::ClientRecvAccept)
    }
    #[cfg(test)]
    pub fn test_client_recv_finish_server(&mut self) -> Result<(), ApplicationHandshakeError> {
        self.apply(HandshakeEvent::ClientRecvFinishServer)
    }
    #[cfg(test)]
    pub fn test_server_recv_hello(&mut self) -> Result<(), ApplicationHandshakeError> {
        self.apply(HandshakeEvent::ServerRecvHello)
    }
    #[cfg(test)]
    pub fn test_server_send_accept(&mut self) -> Result<(), ApplicationHandshakeError> {
        self.apply(HandshakeEvent::ServerSendAccept)
    }
    #[cfg(test)]
    pub fn test_server_recv_finish_client(&mut self) -> Result<(), ApplicationHandshakeError> {
        self.apply(HandshakeEvent::ServerRecvFinishClient)
    }
    #[cfg(test)]
    pub fn test_server_send_finish_server(&mut self) -> Result<(), ApplicationHandshakeError> {
        self.apply(HandshakeEvent::ServerSendFinishServer)
    }

    /// Final step: derive and install transport keys; transition to `Complete`.
    ///
    /// # Errors
    /// Returns `ApplicationHandshakeError::ValidationError` if not in
    /// `HandshakeState::ReadyToComplete` or if key derivation / PRK establishment
    /// fails.
    pub fn complete(
        &mut self,
        th: [u8; 48],
        hybrid_shared: &[u8],
    ) -> Result<(), ApplicationHandshakeError> {
        if self.state != HandshakeState::ReadyToComplete {
            return Err(ApplicationHandshakeError::ValidationError(
                "FSM not ready to complete".into(),
            ));
        }
        if self.prk.is_none() {
            self.prk = Some(prk_from(&th, hybrid_shared));
        }
        if self.writes.is_none() {
            let prk = self.prk.as_ref().ok_or_else(|| {
                ApplicationHandshakeError::ValidationError("PRK not available".into())
            })?;
            let wk: WriteKeys = derive_keys(&th, prk)?;
            self.writes = Some(wk);
        }
        let writes = self
            .writes
            .take()
            .ok_or_else(|| ApplicationHandshakeError::ValidationError("writes missing".into()))?;
        let WriteKeys { client, server } = writes;
        self.conn.install_keys(client, server);
        self.conn.set_seqs(self.next_cli_write, self.next_srv_write);
        self.apply(HandshakeEvent::Complete)
    }

    /// Current handshake state.
    pub fn state(&self) -> HandshakeState {
        self.state
    }
    /// Mutable reference to underlying `KeySink` for advanced integration.
    pub fn conn_mut(&mut self) -> &mut C {
        &mut self.conn
    }
    /// Consume the FSM returning the underlying connection object.
    pub fn into_inner(self) -> C {
        self.conn
    }
}
