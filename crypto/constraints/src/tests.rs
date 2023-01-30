use entropy_shared::{Acl, AclKind, Architecture};

use crate::{
    constraint::Constraint,
    tx::{evm::Evm, utils::parse_tx_request_json},
};

#[test]
fn should_parse_json_evm_tx_request() {
    // copied from https://ethereum.org/en/developers/docs/transactions/#whats-a-transaction
    let evm_tx_request_json = r#"{
        "from": "0x1923f626bb8dc025849e00f99c25fe2b2f7fb0db",
        "gas": "0x55555",
        "maxFeePerGas": "0x1234",
        "maxPriorityFeePerGas": "0x1234",
        "input": "0xabcd",
        "nonce": "0x0",
        "to": "0x07a565b7ed7d7a678680a4c162885bedbb695fe0",
        "value": "0x1234"
    }"#;

    let basic_tx = parse_tx_request_json::<Evm>(evm_tx_request_json.to_string()).unwrap();

    println!("Parsed tx: {basic_tx:?}");
}

#[test]
fn should_error_on_invalid_json_evm_tx_request() {
    // missing "from" field
    let evm_tx_request_json = r#"{
        "gas": "0x55555",
        "maxFeePerGas": "0x1234",
        "maxPriorityFeePerGas": "0x1234",
        "input": "0xabcd",
        "nonce": "0x0",
        "to": "0x07a565b7ed7d7a678680a4c162885bedbb695fe0",
        "value": "0x1234"
    }"#;

    let basic_tx_result = parse_tx_request_json::<Evm>(evm_tx_request_json.to_string());

    assert!(basic_tx_result.is_err());
}

#[test]
fn should_fail_if_evm_address_not_h160() {
    // changed length of from address
    let evm_tx_request_json = r#"{
        "from": "0x1923f8dc025849e00f99c25fe2b2f7fb0db",
        "gas": "0x55555",
        "maxFeePerGas": "0x1234",
        "maxPriorityFeePerGas": "0x1234",
        "input": "0xabcd",
        "nonce": "0x0",
        "to": "0x07a565b7ed7d7a678680a4c162885bedbb695fe0",
        "value": "0x1234"
    }"#;

    let basic_tx_result = parse_tx_request_json::<Evm>(evm_tx_request_json.to_string());

    assert!(basic_tx_result.is_err());

    println!("{basic_tx_result:?}");
}

#[test]
fn test_allow_list() {
    let evm_tx_request_json = r#"{
        "from": "0x1923f626bb8dc025849e00f99c25fe2b2f7fb0db",
        "gas": "0x55555",
        "maxFeePerGas": "0x1234",
        "maxPriorityFeePerGas": "0x1234",
        "input": "0xabcd",
        "nonce": "0x0",
        "to": "0x07a565b7ed7d7a678680a4c162885bedbb695fe0",
        "value": "0x1234"
    }"#;

    let tx_result = parse_tx_request_json::<Evm>(evm_tx_request_json.to_string());
    assert!(tx_result.is_ok());
    let tx = tx_result.unwrap();
    let to = tx.to.unwrap();

    // Assert that an allow list with no items in it does not evaluate to true.
    let constraint = Acl::<<Evm as Architecture>::Address> {
        kind: AclKind::Allow,
        addresses: Vec::default(),
        allow_null_recipient: true,
    };
    let evaluation = constraint.eval(tx.clone());
    assert!(evaluation.is_ok());
    assert!(!evaluation.unwrap());

    // Assert that an allow list with a valid item in it evaluates to true.
    let constraint_2 = Acl::<<Evm as Architecture>::Address> {
        kind: AclKind::Allow,
        addresses: vec![to],
        allow_null_recipient: true,
    };
    let evaluation_2 = constraint_2.eval(tx);
    assert!(evaluation_2.is_ok());
    assert!(evaluation_2.unwrap());
}

#[test]
fn test_deny_list() {
    let evm_tx_request_json = r#"{
        "from": "0x1923f626bb8dc025849e00f99c25fe2b2f7fb0db",
        "gas": "0x55555",
        "maxFeePerGas": "0x1234",
        "maxPriorityFeePerGas": "0x1234",
        "input": "0xabcd",
        "nonce": "0x0",
        "to": "0x07a565b7ed7d7a678680a4c162885bedbb695fe0",
        "value": "0x1234"
    }"#;

    let tx_result = parse_tx_request_json::<Evm>(evm_tx_request_json.to_string());
    assert!(tx_result.is_ok());
    let tx = tx_result.unwrap();
    let to = tx.to.unwrap();

    // Assert that a deny list with no items in it does evaluates to true.
    let constraint = Acl::<<Evm as Architecture>::Address> {
        kind: AclKind::Deny,
        addresses: Vec::default(),
        allow_null_recipient: true,
    };
    let evaluation = constraint.eval(tx.clone());
    assert!(evaluation.is_ok());
    assert!(evaluation.unwrap());

    // Assert that a deny list with the specified recipient evalutes to false.
    let constraint_2 = Acl::<<Evm as Architecture>::Address> {
        kind: AclKind::Deny,
        addresses: vec![to],
        allow_null_recipient: true,
    };
    let evaluation_2 = constraint_2.eval(tx);
    assert!(evaluation_2.is_ok());
    assert!(!evaluation_2.unwrap());
}

#[test]
fn test_allow_null_recip() {
    let evm_tx_request_json = r#"{
        "from": "0x1923f626bb8dc025849e00f99c25fe2b2f7fb0db",
        "gas": "0x55555",
        "maxFeePerGas": "0x1234",
        "maxPriorityFeePerGas": "0x1234",
        "input": "0xabcd",
        "nonce": "0x0",
        "value": "0x1234"
    }"#;

    let tx_result = parse_tx_request_json::<Evm>(evm_tx_request_json.to_string());
    assert!(tx_result.is_ok());
    let tx = tx_result.unwrap();

    let constraint = Acl::<<Evm as Architecture>::Address> {
        kind: AclKind::Deny,
        addresses: Vec::default(),
        allow_null_recipient: false,
    };
    let evaluation = constraint.eval(tx.clone());
    assert!(evaluation.is_err());

    let constraint_2 = Acl::<<Evm as Architecture>::Address> {
        kind: AclKind::Allow,
        addresses: Vec::default(),
        allow_null_recipient: true,
    };
    let evaluation_2 = constraint_2.eval(tx);
    assert!(evaluation_2.is_ok());
    assert!(evaluation_2.unwrap());
}
