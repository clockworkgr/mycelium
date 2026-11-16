//! ADR-011's authenticated channel handshake, independent of how frames move.
//!
//! The handshake was written for the internet transport, where frames are
//! length-prefixed on a TCP stream. BLE has no stream: the platform layer
//! hands whole frames in and takes whole frames out, and nothing can block
//! waiting for the next one. ADR-021 requires one proof format and one
//! implementation across BLE, Wi-Fi Direct and internet — "the mistakes in
//! this area are exactly the ones that come from a second path nobody looks
//! at" — so the handshake lives here as a state machine and each transport
//! drives it with the frames it has:
//!
//! ```text
//! start(identity, listen_port)  ->  Hello body to send         (cleartext)
//! accept_hello(peer's Hello)    ->  Confirm body to send       (sealed)
//! accept_confirm(peer's Confirm) ->  Channel { peer, keys }
//! ```
//!
//! The bodies are the same bytes in the same order whichever transport
//! carries them, so [`internet::handshake`](super::internet::handshake) is
//! four framed reads and writes around this, and a local link feeds it
//! reassembled frames as they arrive. A local link signs `listen_port = 0`:
//! there is no port to dial on a radio, and the field is covered by the
//! signature either way, so no transport can reinterpret another's hello as
//! carrying an address it does not have.
//!
//! What the handshake proves, and why it cannot be relayed, is ADR-011's
//! argument and is recorded in [`mycelium_crypto::channel`]: the signature
//! covers a *fresh ephemeral key*, the channel keys come from that key's
//! secret, and nothing is installed until the peer has sealed a frame under
//! them. An attacker can forward a victim's signed hello and the signature
//! still verifies; it cannot produce the confirmation.

use mycelium_crypto::channel::{channel_hello_payload, ChannelHandshake, ChannelKeys, FrameCipher};
use mycelium_crypto::identity::{node_id_from_public_key, verify_signature_bytes, Identity};
use mycelium_protocol::types::NodeId;

use crate::dht::rpc::{deserialize_wire_message, encode_body, ChannelWireMessage};

use super::TransportError;

/// A peer that has proved possession of the identity key behind its NodeId
/// *and* of the channel key derived from the ephemeral key it signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    pub node_id: NodeId,
    pub identity_key: [u8; 32],
    /// The port the peer says it accepts connections on, covered by its
    /// signature so a man in the middle cannot redirect later dials. Zero on
    /// a local transport, which has no dialable address.
    pub listen_port: u16,
}

/// The result of a completed handshake: who the peer is, and the channel.
pub struct Channel {
    pub peer: AuthenticatedPeer,
    /// Identifies this channel. Both ends derive the same value, and it
    /// differs per connection, which is what makes it a usable tie-break when
    /// two connections to one peer exist at once.
    pub transcript: [u8; 32],
    /// Our sending direction, counted from the sealed confirmation.
    pub send: FrameCipher,
    /// The peer's sending direction.
    pub recv: FrameCipher,
}

/// Our side of a handshake in progress.
///
/// Each step consumes what it needs and refuses to run twice, so a transport
/// that feeds frames in as they arrive cannot be talked into restarting a
/// handshake mid-way or into confirming before it has a key.
pub struct ChannelHandshakeDriver {
    identity_key: [u8; 32],
    /// Taken by `accept_hello`: our ephemeral secret is used once.
    exchange: Option<ChannelHandshake>,
    /// Set by `accept_hello`, taken by `accept_confirm`.
    pending: Option<(ChannelKeys, AuthenticatedPeer)>,
}

impl ChannelHandshakeDriver {
    /// Begin a handshake, returning the cleartext `Hello` body to send.
    ///
    /// Both ends do this as soon as the link exists; the handshake is
    /// symmetric, so neither needs to know which of them dialled.
    pub fn start(identity: &Identity, listen_port: u16) -> (Self, Vec<u8>) {
        let exchange = ChannelHandshake::new();
        let ephemeral_public = exchange.public_key();
        let identity_key = identity.public_key_bytes();
        let signature = identity
            .sign(&channel_hello_payload(
                &ephemeral_public,
                &identity_key,
                listen_port,
            ))
            .to_bytes();
        let hello = encode_body(&ChannelWireMessage::Hello {
            identity_key,
            ephemeral_public,
            listen_port,
            signature,
        });
        (
            Self {
                identity_key,
                exchange: Some(exchange),
                pending: None,
            },
            hello,
        )
    }

    /// Take the peer's cleartext `Hello` and return the sealed `Confirm` body.
    ///
    /// Key confirmation is not optional. Without it a relay that forwarded
    /// someone else's hello would install itself as a peer that silently
    /// drops everything.
    pub fn accept_hello(&mut self, body: &[u8]) -> Result<Vec<u8>, TransportError> {
        let exchange = self
            .exchange
            .take()
            .ok_or_else(|| TransportError::Other("a second hello on one handshake".to_string()))?;

        let (peer_identity_key, peer_ephemeral, peer_port, peer_signature) =
            match deserialize_wire_message(body)
                .map_err(|e| TransportError::Other(e.to_string()))?
            {
                ChannelWireMessage::Hello {
                    identity_key,
                    ephemeral_public,
                    listen_port,
                    signature,
                } => (identity_key, ephemeral_public, listen_port, signature),
                other => {
                    return Err(TransportError::Other(format!(
                        "expected a hello, got {}",
                        discriminant_name(&other)
                    )))
                }
            };

        verify_signature_bytes(
            &peer_identity_key,
            &channel_hello_payload(&peer_ephemeral, &peer_identity_key, peer_port),
            &peer_signature,
        )
        .map_err(|_| TransportError::Other("hello signature did not verify".to_string()))?;

        let mut keys = exchange
            .complete(&peer_ephemeral, &self.identity_key, &peer_identity_key)
            .map_err(|e| TransportError::Other(e.to_string()))?;

        let confirm = encode_body(&ChannelWireMessage::Confirm {
            transcript: keys.transcript,
        });
        let sealed = keys
            .send
            .seal(&confirm)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        self.pending = Some((
            keys,
            AuthenticatedPeer {
                // Derived, never carried: the §14.3 binding cannot be
                // violated by construction.
                node_id: node_id_from_public_key(&peer_identity_key),
                identity_key: peer_identity_key,
                listen_port: peer_port,
            },
        ));
        Ok(sealed)
    }

    /// Take the peer's sealed `Confirm` and return the established channel.
    pub fn accept_confirm(&mut self, sealed: &[u8]) -> Result<Channel, TransportError> {
        let (mut keys, peer) = self
            .pending
            .take()
            .ok_or_else(|| TransportError::Other("a confirmation before any hello".to_string()))?;

        let opened = keys.recv.open(sealed).map_err(|_| {
            TransportError::Other("peer could not prove the channel key".to_string())
        })?;
        match deserialize_wire_message(&opened).map_err(|e| TransportError::Other(e.to_string()))? {
            ChannelWireMessage::Confirm { transcript } if transcript == keys.transcript => {}
            ChannelWireMessage::Confirm { .. } => {
                return Err(TransportError::Other(
                    "peer confirmed a different transcript".to_string(),
                ))
            }
            other => {
                return Err(TransportError::Other(format!(
                    "expected a confirmation, got {}",
                    discriminant_name(&other)
                )))
            }
        }

        Ok(Channel {
            peer,
            transcript: keys.transcript,
            send: keys.send,
            recv: keys.recv,
        })
    }
}

/// Name a frame for a log line or an error, without printing its contents.
pub(crate) fn discriminant_name(msg: &ChannelWireMessage) -> &'static str {
    match msg {
        ChannelWireMessage::MeshData { .. } => "mesh data",
        ChannelWireMessage::Dht(_) => "dht request",
        ChannelWireMessage::DhtReply(_) => "dht reply",
        ChannelWireMessage::Hello { .. } => "hello",
        ChannelWireMessage::Confirm { .. } => "confirmation",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run both sides to completion the way a transport does, returning each
    /// end's channel.
    fn complete_pair(a: &Identity, b: &Identity) -> (Channel, Channel) {
        let (mut a_driver, a_hello) = ChannelHandshakeDriver::start(a, 1);
        let (mut b_driver, b_hello) = ChannelHandshakeDriver::start(b, 2);
        let a_confirm = a_driver.accept_hello(&b_hello).expect("b's hello");
        let b_confirm = b_driver.accept_hello(&a_hello).expect("a's hello");
        let a_channel = a_driver.accept_confirm(&b_confirm).expect("b's confirm");
        let b_channel = b_driver.accept_confirm(&a_confirm).expect("a's confirm");
        (a_channel, b_channel)
    }

    #[test]
    fn test_both_ends_prove_each_other_and_agree_on_the_channel() {
        let a = Identity::generate();
        let b = Identity::generate();
        let (a_channel, b_channel) = complete_pair(&a, &b);

        assert_eq!(a_channel.peer.node_id, b.node_id(), "derived from the key");
        assert_eq!(b_channel.peer.node_id, a.node_id());
        assert_eq!(a_channel.transcript, b_channel.transcript);
        assert_eq!(a_channel.peer.listen_port, 2, "the signed port is carried");
    }

    /// The relay ADR-011 describes: forwarding a victim's signed hello gets
    /// the attacker past the signature and no further.
    #[test]
    fn test_a_forwarded_hello_cannot_be_confirmed() {
        let victim = Identity::generate();
        let server = Identity::generate();
        let attacker = Identity::generate();

        let (_victim_driver, victim_hello) = ChannelHandshakeDriver::start(&victim, 9736);
        let (mut server_driver, _) = ChannelHandshakeDriver::start(&server, 9736);
        // The server accepts the signature — it is the victim's, and valid.
        let server_confirm = server_driver
            .accept_hello(&victim_hello)
            .expect("a valid signature from the victim");

        // The attacker holds no ephemeral secret for the key it forwarded, so
        // the best it can do is seal under a channel of its own.
        let (mut attacker_driver, _) = ChannelHandshakeDriver::start(&attacker, 9736);
        let attacker_confirm = attacker_driver
            .accept_hello(&victim_hello)
            .expect("the attacker can derive its own channel");
        assert!(
            server_driver.accept_confirm(&attacker_confirm).is_err(),
            "the server must not accept a confirmation from another channel"
        );
        assert!(
            !server_confirm.is_empty(),
            "the server did seal a confirmation, to the victim's ephemeral key"
        );
    }

    #[test]
    fn test_a_tampered_signature_is_refused() {
        let a = Identity::generate();
        let b = Identity::generate();
        let (_, mut b_hello) = ChannelHandshakeDriver::start(&b, 0);
        let last = b_hello.len() - 1;
        b_hello[last] ^= 0x01;

        let (mut a_driver, _) = ChannelHandshakeDriver::start(&a, 0);
        let err = a_driver.accept_hello(&b_hello).expect_err("refused");
        assert!(err.to_string().contains("signature"), "{err}");
    }

    #[test]
    fn test_a_confirmation_before_a_hello_is_refused() {
        let a = Identity::generate();
        let (mut driver, _) = ChannelHandshakeDriver::start(&a, 0);
        assert!(
            driver.accept_confirm(&[0u8; 49]).is_err(),
            "nothing can be confirmed before a key exists"
        );
    }

    #[test]
    fn test_a_second_hello_on_one_handshake_is_refused() {
        let a = Identity::generate();
        let b = Identity::generate();
        let (_, b_hello) = ChannelHandshakeDriver::start(&b, 0);
        let (mut a_driver, _) = ChannelHandshakeDriver::start(&a, 0);
        a_driver.accept_hello(&b_hello).expect("the first hello");
        assert!(
            a_driver.accept_hello(&b_hello).is_err(),
            "our ephemeral secret is used once"
        );
    }

    #[test]
    fn test_mesh_data_in_place_of_a_hello_is_refused() {
        let a = Identity::generate();
        let (mut driver, _) = ChannelHandshakeDriver::start(&a, 0);
        let body = encode_body(&ChannelWireMessage::MeshData {
            sender_id: a.node_id(),
            data: vec![1, 2, 3],
        });
        let err = driver.accept_hello(&body).expect_err("refused");
        assert!(err.to_string().contains("expected a hello"), "{err}");
    }
}
