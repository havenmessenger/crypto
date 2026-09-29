//! Read-only access to the group member's own leaf HPKE private key.
//!
//! openmls keeps its `EncryptionKeyPair` and the accessor for the private half crate-private, and
//! the only supported way to reach the key is the storage provider. This module asks the provider
//! for the pair through openmls's storage traits, deserializing into a private mirror of the
//! stored shape. Three properties hold by construction:
//!
//! * the mirror can be read and never written: its `Serialize` implementation always fails, so it
//!   cannot be stored back;
//! * no function outside this module receives the key as anything but a `Zeroizing` buffer used for
//!   one HPKE open, and none returns it to a caller of the crate;
//! * a stored layout this mirror does not understand yields `None`, never a guess.
//!
//! The mirror follows the layout of the in-memory storage provider used with openmls 0.8.1; a test
//! pins the openmls version and round-trips a real key, so an upgrade or a layout change fails
//! loudly instead of silently.

use openmls::prelude::{GroupEpoch, GroupId, MlsGroup};
use openmls::treesync::EncryptionKey;
use openmls_traits::storage::{traits, Entity, StorageProvider, CURRENT_VERSION};
use openmls_traits::types::HpkePrivateKey;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize, Serializer};
use tls_codec::Serialize as TlsSerialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct StoredPrivateKey {
    key: HpkePrivateKey,
}

#[derive(Deserialize)]
pub(super) struct StoredKeyPair {
    public_key: EncryptionKey,
    private_key: StoredPrivateKey,
}

impl Serialize for StoredKeyPair {
    fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            "the key pair mirror is read-only",
        ))
    }
}

impl Entity<CURRENT_VERSION> for StoredKeyPair {}
impl traits::HpkeKeyPair<CURRENT_VERSION> for StoredKeyPair {}

fn same_key(a: &EncryptionKey, b: &EncryptionKey) -> bool {
    match (a.tls_serialize_detached(), b.tls_serialize_detached()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn private_bytes(pair: &StoredKeyPair) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(pair.private_key.key.to_vec())
}

/// The private HPKE key matching the group's own leaf, if the provider holds it. Keys generated
/// at group creation or join sit in the epoch key-pair list; a key from a later self-update sits
/// in the standalone slot. Both are consulted.
pub(super) fn own_leaf_private_key<P: OpenMlsProvider>(
    provider: &P,
    group: &MlsGroup,
) -> Option<Zeroizing<Vec<u8>>> {
    let own_key = group.own_leaf()?.encryption_key();
    let storage = provider.storage();

    let epoch_pairs = storage
        .encryption_epoch_key_pairs::<GroupId, GroupEpoch, StoredKeyPair>(
            group.group_id(),
            &group.epoch(),
            group.own_leaf_index().u32(),
        )
        .ok()?;
    if let Some(pair) = epoch_pairs
        .iter()
        .find(|pair| same_key(&pair.public_key, own_key))
    {
        return Some(private_bytes(pair));
    }

    let standalone = storage
        .encryption_key_pair::<StoredKeyPair, EncryptionKey>(own_key)
        .ok()??;
    same_key(&standalone.public_key, own_key).then(|| private_bytes(&standalone))
}
