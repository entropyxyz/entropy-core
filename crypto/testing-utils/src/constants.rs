use hex_literal::hex;
use sp_core::crypto::AccountId32;

lazy_static! {
    pub static ref ALICE_STASH_ADDRESS: AccountId32 = hex!["be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f"].into();
    pub static ref RANDOM_ACCOUNT: AccountId32 = hex!["8676839ca1e196624106d17c56b1efbb90508a86d8053f7d4fcd21127a9f7565"].into();
    pub static ref VALIDATOR_1_STASH_ID: AccountId32 =
        hex!["be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f"].into(); // alice stash;
    pub static ref BOB_STASH_ADDRESS: AccountId32 =
        hex!["fe65717dad0447d715f660a0a58411de509b42e6efb8375f562f58a554d5860e"].into(); // subkey inspect //Bob//stash
    pub static ref X25519_PUBLIC_KEYS: Vec<[u8; 32]> = vec![
        vec![
            10, 192, 41, 240, 184, 83, 178, 59, 237, 101, 45, 109, 13, 230, 155, 124, 195, 141,
            148, 249, 55, 50, 238, 252, 133, 181, 134, 30, 144, 247, 58, 34,
        ]
        .try_into()
        .unwrap(),
        vec![
            225, 48, 135, 211, 227, 213, 170, 21, 1, 189, 118, 158, 255, 87, 245, 89, 36, 170, 169,
            181, 68, 201, 210, 178, 237, 247, 101, 80, 153, 136, 102, 10,
        ]
        .try_into()
        .unwrap(),
    ];
}
