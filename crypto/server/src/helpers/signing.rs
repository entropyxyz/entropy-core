use std::{collections::HashMap, sync::Mutex};

use tofn::sdk::api::RecoverableSignature;

// TODO: JA Remove all below, temporary
/// The state used to temporarily store completed signatures
#[derive(Debug)]
pub struct SignatureState {
    pub signatures: Mutex<HashMap<String, RecoverableSignature>>,
}

impl SignatureState {
    pub fn new() -> SignatureState {
        let signatures = Mutex::new(HashMap::new());
        SignatureState { signatures }
    }

    pub fn insert(&self, key: [u8; 32], value: &RecoverableSignature) {
        let mut signatures = self.signatures.lock().unwrap_or_else(|e| e.into_inner());
        println!("inside insert value: {:?}", value.clone());
        signatures.insert(hex::encode(key), *value);
    }

    pub fn get(&self, key: &String) -> [u8; 65] {
        let signatures = self.signatures.lock().unwrap_or_else(|e| e.into_inner());
        let result = *signatures.get(key).unwrap();
        result.as_ref().try_into().expect("slice with incorrect length")
    }

    pub fn drain(&self) {
        let mut signatures = self.signatures.lock().unwrap_or_else(|e| e.into_inner());
        let _ = signatures.drain();
    }
}
