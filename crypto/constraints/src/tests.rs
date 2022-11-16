use crate::tx::evm::EVM;
use crate::tx::parse_raw_tx_json;
use crate::whitelist::is_on_whitelist;

#[test]
fn test_whitelist() {
    let address = vec![1u8];
    let list = vec![vec![2u8], vec![1u8]];

    // No whitelist not set passes check
    assert!(is_on_whitelist(vec![], &address));
    // on list
    assert!(is_on_whitelist(list.clone(), &address));
    // not on list
    assert!(!is_on_whitelist(list, &vec![3u8]));
}

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

    let basic_tx = parse_raw_tx_json::<EVM>(evm_tx_request_json.to_string()).unwrap();

    println!("Parsed tx: {:?}", basic_tx);
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

    let basic_tx_result = parse_raw_tx_json::<EVM>(evm_tx_request_json.to_string());

    assert!(basic_tx_result.is_err());
}
