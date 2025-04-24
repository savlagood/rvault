use crate::utils::base64;
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};
use shamir::SecretData;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SharedKeysError {
    #[error("Invalid share ID: {0} - must be greater that 0")]
    ShareId(u8),

    #[error("Invalid shared keys")]
    SharedKeys,

    #[error("Invalid shared keys settings. The inequality must be satisfied: 0 < threshold < total_keys")]
    Settings,
}

impl From<base64::Base64Error> for SharedKeysError {
    fn from(_err: base64::Base64Error) -> Self {
        SharedKeysError::SharedKeys
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SharedKeysSettings {
    pub threshold: u8,
    pub total_keys: u8,
}

impl SharedKeysSettings {
    pub fn assert_valid(&self) -> Result<(), SharedKeysError> {
        if !(1 < self.threshold && self.threshold < self.total_keys) {
            Err(SharedKeysError::Settings)
        } else {
            Ok(())
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SharedKeys {
    shares: Vec<String>,
}

impl SharedKeys {
    pub fn count(&self) -> usize {
        self.shares.len()
    }

    pub fn from_key(key: Vec<u8>, settings: &SharedKeysSettings) -> Result<Self, SharedKeysError> {
        let secret = base64::encode(&key);
        let secret_data = SecretData::with_secret(&secret, settings.threshold);

        let range = 1..=u8::MAX;
        let indices = choose_random_indices(range, settings.total_keys);

        let shares = indices
            .into_iter()
            .map(|id| {
                secret_data
                    .get_share(id)
                    .map(|shared_key| base64::encode(&shared_key))
                    .map_err(|_err| SharedKeysError::ShareId(id))
            })
            .collect::<Result<Vec<String>, SharedKeysError>>()?;

        Ok(Self { shares })
    }

    pub fn into_key(self, threshold: u8) -> Result<Vec<u8>, SharedKeysError> {
        let shared_keys_bytes = self
            .shares
            .into_iter()
            .map(base64::decode)
            .collect::<Result<Vec<Vec<u8>>, _>>()?;

        let recovered_key_str = SecretData::recover_secret(threshold, shared_keys_bytes)
            .ok_or(SharedKeysError::SharedKeys)?;
        let recovered_key_bytes = base64::decode(recovered_key_str)?;

        Ok(recovered_key_bytes)
    }
}

fn choose_random_indices(range: std::ops::RangeInclusive<u8>, total: u8) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    range.choose_multiple(&mut rng, total as usize)
}
