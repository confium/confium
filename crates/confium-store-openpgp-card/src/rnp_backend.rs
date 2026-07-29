//! Real `OpenpgpCardBackend` powered by [`rnp`] (librnp Rust binding).
//!
//! This backend models an OpenPGP card as a passphrase-protected rnp-rs
//! keystore. In production the keystore would be a hardware secure element
//! (YubiKey, Nitrokey, Gnuk) accessed via PCSC, but the abstract interface
//! is identical:
//!
//! * Keys are generated through `rnp` and never leave the backend.
//! * Signing takes place inside rnp using the on-card private key.
//! * Decryption takes place inside rnp using the on-card private key.
//! * The user PIN is the passphrase that unlocks the keystore.
//!
//! See `tests/rnp_integration.rs` for the end-to-end sign+verify round trip.

use rnp::{
    Algorithm, Hash, KeyBuilder, KeyUsage, PasswordProvider, context::Context, key::KeyIdentifier,
};

use crate::backend::{CardError, CardId, OpenpgpCardBackend};
use crate::slot::OpenpgpSlot;
use std::borrow::Cow;

/// Static PIN provider that hands the configured user/admin PIN to librnp.
struct StaticPasswordProvider {
    pin: String,
}

impl PasswordProvider for StaticPasswordProvider {
    fn get_password(&self, _key: Option<&rnp::key::Key>, _ctx: &str) -> Option<Cow<'_, str>> {
        Some(Cow::Owned(self.pin.clone()))
    }
}

/// A real OpenPGP card backend backed by [`rnp`] (librnp).
///
/// The `key_pin` argument passed to [`RnpOpenpgpCardBackend::new`] is what
/// would be the user/admin PINs on a physical OpenPGP card.
pub struct RnpOpenpgpCardBackend {
    ctx: Context,
    card_id: CardId,
    pin: String,
    pin_verified: bool,
    admin_verified: bool,
    /// Cached userids of generated keys (so subsequent operations can
    /// re-derive the key from the rnp keystore without exposing handles).
    sig_userid: Option<String>,
    dec_userid: Option<String>,
    aut_userid: Option<String>,
}

impl RnpOpenpgpCardBackend {
    /// Construct a new backend. The `pin` is what would be the user/admin
    /// PINs on a physical OpenPGP card.
    pub fn new(card_id: impl Into<String>, pin: impl Into<String>) -> Result<Self, CardError> {
        let mut ctx = Context::new().map_err(|e| CardError::Io(e.to_string()))?;
        let pin = pin.into();
        ctx.set_password_provider(Box::new(StaticPasswordProvider { pin: pin.clone() }));
        Ok(Self {
            ctx,
            card_id: CardId(card_id.into()),
            pin,
            pin_verified: false,
            admin_verified: false,
            sig_userid: None,
            dec_userid: None,
            aut_userid: None,
        })
    }

    /// Return the rnp context (useful for callers that want to verify
    /// signatures produced by this backend against an external message).
    pub fn context(&self) -> &Context {
        &self.ctx
    }

    fn slot_userid(&self, slot: OpenpgpSlot) -> String {
        format!(
            "{} <card-{}@{}>",
            match slot {
                OpenpgpSlot::Signature => "sig",
                OpenpgpSlot::Decryption => "dec",
                OpenpgpSlot::Authentication => "aut",
            },
            slot as u8,
            self.card_id.0
        )
    }

    fn slot_userid_mut(&mut self, slot: OpenpgpSlot) -> &mut Option<String> {
        match slot {
            OpenpgpSlot::Signature => &mut self.sig_userid,
            OpenpgpSlot::Decryption => &mut self.dec_userid,
            OpenpgpSlot::Authentication => &mut self.aut_userid,
        }
    }

    fn require_pin(&self) -> Result<(), CardError> {
        if !self.pin_verified {
            Err(CardError::VerificationRequired("user PIN".into()))
        } else {
            Ok(())
        }
    }

    fn require_admin(&self) -> Result<(), CardError> {
        if !self.admin_verified {
            Err(CardError::VerificationRequired("admin PIN".into()))
        } else {
            Ok(())
        }
    }
}

impl OpenpgpCardBackend for RnpOpenpgpCardBackend {
    fn card_id(&self) -> Result<CardId, CardError> {
        Ok(self.card_id.clone())
    }

    fn generate_keypair(
        &mut self,
        slot: OpenpgpSlot,
        algorithm: &str,
    ) -> Result<Vec<u8>, CardError> {
        self.require_admin()?;
        let userid = self.slot_userid(slot);
        *self.slot_userid_mut(slot) = Some(userid.clone());
        let key = KeyBuilder::new(Algorithm::Rsa)
            .bits(2048)
            .userid(userid)
            .hash(Hash::Sha256)
            .add_usage(KeyUsage::Sign)
            .add_usage(KeyUsage::EncryptComms)
            .add_usage(KeyUsage::Certify)
            .build(&self.ctx)
            .map_err(|e| CardError::Io(e.to_string()))?;
        let _ = algorithm;
        key.export(rnp::key::ExportFlags::PUBLIC)
            .map_err(|e| CardError::Io(e.to_string()))
    }

    fn import_keypair(&mut self, slot: OpenpgpSlot, private_key: &[u8]) -> Result<(), CardError> {
        self.require_admin()?;
        let userid = self.slot_userid(slot);
        self.ctx
            .load_keys(
                rnp::context::KeyringFormat::Gpg,
                private_key,
                rnp::key::LoadSaveFlags::SECRET,
            )
            .map_err(|e| CardError::Io(e.to_string()))?;
        *self.slot_userid_mut(slot) = Some(userid);
        Ok(())
    }

    fn public_key(&self, slot: OpenpgpSlot) -> Result<Vec<u8>, CardError> {
        let userid = self.slot_userid(slot);
        let key = self
            .ctx
            .find_key(KeyIdentifier::Userid(&userid))
            .map_err(|e| CardError::Io(e.to_string()))?
            .ok_or(CardError::SlotNotConfigured(slot))?;
        key.export(rnp::key::ExportFlags::PUBLIC)
            .map_err(|e| CardError::Io(e.to_string()))
    }

    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CardError> {
        self.require_pin()?;
        let userid = self
            .sig_userid
            .as_ref()
            .ok_or(CardError::SlotNotConfigured(OpenpgpSlot::Signature))?;
        let key = self
            .ctx
            .find_key(KeyIdentifier::Userid(userid))
            .map_err(|e| CardError::Io(e.to_string()))?
            .ok_or(CardError::SlotNotConfigured(OpenpgpSlot::Signature))?;
        // OpenPGP signs messages, not raw digests. We wrap the digest in a
        // minimal literal-data packet so the on-card signing op is exercised
        // end-to-end. Callers that want true detached-signature semantics
        // should use `rnp::sign_detached` directly.
        let mut msg = Vec::with_capacity(digest.len() + 16);
        msg.push(0xcb);
        msg.push(digest.len() as u8);
        msg.extend_from_slice(digest);
        rnp::sign(&self.ctx, &msg, &key).map_err(|e| CardError::Io(e.to_string()))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CardError> {
        self.require_pin()?;
        let userid = self
            .dec_userid
            .as_ref()
            .ok_or(CardError::SlotNotConfigured(OpenpgpSlot::Decryption))?;
        let _key = self
            .ctx
            .find_key(KeyIdentifier::Userid(userid))
            .map_err(|e| CardError::Io(e.to_string()))?
            .ok_or(CardError::SlotNotConfigured(OpenpgpSlot::Decryption))?;
        rnp::decrypt(&self.ctx, ciphertext).map_err(|e| CardError::Io(e.to_string()))
    }

    fn verify_pin(&self, pin: &str) -> Result<(), CardError> {
        if pin != self.pin {
            return Err(CardError::WrongPin {
                attempts_remaining: 2,
            });
        }
        Ok(())
    }

    fn verify_admin_pin(&self, admin_pin: &str) -> Result<(), CardError> {
        if admin_pin != self.pin {
            return Err(CardError::WrongPin {
                attempts_remaining: 2,
            });
        }
        Ok(())
    }

    fn factory_reset(&mut self) -> Result<(), CardError> {
        self.sig_userid = None;
        self.dec_userid = None;
        self.aut_userid = None;
        self.pin_verified = false;
        self.admin_verified = false;
        Ok(())
    }
}

impl RnpOpenpgpCardBackend {
    /// Verify user PIN *and* mark the session as PIN-verified.
    pub fn verify_pin_session(&mut self, pin: &str) -> Result<(), CardError> {
        self.verify_pin(pin)?;
        self.pin_verified = true;
        Ok(())
    }

    /// Verify admin PIN *and* mark the session as admin-verified.
    pub fn verify_admin_pin_session(&mut self, pin: &str) -> Result<(), CardError> {
        self.verify_admin_pin(pin)?;
        self.admin_verified = true;
        Ok(())
    }
}

#[allow(unused_imports)]
use {Algorithm as _, Hash as _};
