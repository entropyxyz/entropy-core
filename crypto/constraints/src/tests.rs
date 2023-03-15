use crate::{Error, Evm, Evaluate};
use entropy_shared::{Acl, AclKind, Constraints};
use ethers_core::types::{NameOrAddress, Address, TransactionRequest};

// write a test for the eval function of the Evaluate trait
#[cfg(test)]
mod tests {
    use super::*;
    use ethers_core::types::{NameOrAddress, Address, H160};

    #[test]
    fn test_acl_functions_properly() {
        let evm_address_1: [u8; 20] = [1u8; 20];
        let evm_address_2: [u8; 20] = [2u8; 20];
        let evm_address_3: [u8; 20] = [3u8; 20];

        let to_address_1_tx = TransactionRequest {
            to: Some(NameOrAddress::Address(H160::from(evm_address_1))),
            ..Default::default()
        };
        let to_address_2_tx = TransactionRequest {
            to: Some(NameOrAddress::Address(H160::from(evm_address_2))),
            ..Default::default()
        };
        let to_address_3_tx = TransactionRequest {
            to: Some(NameOrAddress::Address(H160::from(evm_address_3))),
            ..Default::default()
        };
        let to_null_recipient_tx = TransactionRequest {
            to: None,
            ..Default::default()
        };


        let allowlisted_acl = Acl::<[u8; 20]> {
            addresses: vec![
                evm_address_1.clone()
            ],
            ..Default::default()
        };

        // should only let allowlisted_tx through
        assert!(allowlisted_acl.eval(to_address_1_tx.clone()).unwrap());
        assert!(!allowlisted_acl.eval(to_address_2_tx.clone()).unwrap());
        assert!(!allowlisted_acl.eval(to_address_3_tx.clone()).unwrap());
        assert!(!allowlisted_acl.eval(to_null_recipient_tx.clone()).unwrap());

        let denylisted_acl = Acl::<[u8; 20]> {
            addresses: vec![
                evm_address_1
            ],
            kind: AclKind::Deny,
            ..Default::default()
        };

        // should only block whitelisted and null recipient txs
        assert!(!denylisted_acl.eval(to_address_1_tx.clone()).unwrap());
        assert!(denylisted_acl.eval(to_address_2_tx.clone()).unwrap());
        assert!(denylisted_acl.eval(to_address_3_tx.clone()).unwrap());
        assert!(!allowlisted_acl.eval(to_null_recipient_tx.clone()).unwrap()); 

        let allowlisted_acl_with_null_recipient = Acl::<[u8; 20]> {
            addresses: vec![
                evm_address_1
            ],
            allow_null_recipient: true,
            ..Default::default()
        };

        assert!(allowlisted_acl_with_null_recipient.eval(to_address_1_tx.clone()).unwrap());
        assert!(!allowlisted_acl_with_null_recipient.eval(to_address_2_tx.clone()).unwrap());
        assert!(!allowlisted_acl_with_null_recipient.eval(to_address_3_tx.clone()).unwrap());
        assert!(allowlisted_acl_with_null_recipient.eval(to_null_recipient_tx.clone()).unwrap());

        let denylisted_acl_with_null_recipient = Acl::<[u8; 20]> {
            addresses: vec![
                evm_address_1
            ],
            kind: AclKind::Deny,
            allow_null_recipient: true,
        };

        // should only block whitelisted
        assert!(!denylisted_acl_with_null_recipient.eval(to_address_1_tx.clone()).unwrap());
        assert!(denylisted_acl_with_null_recipient.eval(to_address_2_tx.clone()).unwrap());
        assert!(denylisted_acl_with_null_recipient.eval(to_address_3_tx.clone()).unwrap());
        assert!(denylisted_acl_with_null_recipient.eval(to_null_recipient_tx.clone()).unwrap()); 


    }
}