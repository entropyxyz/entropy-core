use hex_literal::hex;
use node_primitives::{AccountId};
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use grandpa_primitives::AuthorityId as GrandpaId;
use sp_consensus_babe::AuthorityId as BabeId;
use entropy_runtime::{GenesisConfig};
use crate::chain_spec::{testnet_genesis, devnet_genesis, get_account_id_from_seed, authority_keys_from_seed};
use sp_core::{crypto::UncheckedInto, sr25519};



pub fn devnet_config_genesis() -> GenesisConfig {
    #[rustfmt::skip]
	// stash, controller, session-key
	// generated with secret:
	// for i in 1 2 3 4 ; do for j in stash controller; do subkey inspect "$secret"/fir/$j/$i; done; done
	//
	// and
	//
	// for i in 1 2 3 4 ; do for j in session; do subkey --ed25519 inspect "$secret"//fir//$j//$i; done; done

	let initial_authorities: Vec<(
		AccountId,
		AccountId,
		GrandpaId,
		BabeId,
		ImOnlineId,
		AuthorityDiscoveryId,
	)> = vec![
		(
			// controller -> Sr25519
			// 5DUp9KHrDi8k8R4e2rPZhbxudUzEuNtxwUvfbCYtCZRA4no6
			hex!["3e9f4983e0cd02803c0d2e0fd58ea8d89e0a279e829a1aa9fdc1162a1a53e359"].into(),
			// stash -> Sr25519
			// 5FNHcKqJzVGfSCFNAsw3YfPdHioKN7Usdtd32vBEkU1LjVV7
			hex!["921d7e7421fa0120839c5f4f29b651421720d79e3885856abb127ed8d5744d22"].into(),
			// grandpa -> ed25519
			// 5H9kQJyK9THVhvgcKBSGWGidjSezNTdUn5p5Jc2c75kV6Txk
			hex!["e105f69f91ddfa8499434c6cf03f0208ee26bf57446f70558ef6bc5bfbdcd258"]
				.unchecked_into(),
			// babe -> Sr25519
			// 5D7MndGJ3BVvm7sAcuVuXffVuDfTrSjS4cSieVJcQeqLfycR
			hex!["2e4268b609fac59c448d755d3b63ef30d897c6f7e0eeb3eeff3e7d0e0d93cc12"]
				.unchecked_into(),
			// im online -> Sr25519
			// 5F4RQ5dTKKyvmkuVuKTTUUqDFm9oRe8gZRpmU8fhDtpxH4ar
			hex!["847d4be0524b7eac945860cfd1bcd8d40e6cfcfbc7634251ddcdb89c54d4356d"]
				.unchecked_into(),
			// authority discovery -> Sr25519
			// 5FBo1QLcDGzH9zZcpE59dFJjWnqqpXnT6ZcwF6y2fGByGNKf
			hex!["8a1cc1b2c4cd82693fc73714a4ef9937c1a413f612e0f46e095b3cf60f928f73"]
				.unchecked_into(),
		),
		(
			// 5Gen3ZR6zY4bo55KwioD6bE57GVv8QnBEzL7b5t9rFUZXGE2
			hex!["caed5ff7554fd17349372086115af48ffa4329ad92eb33b62f8ef3de425f4c42"].into(),
			// 5CY72U7tqHNGspa2jE9MpJomDtBnzNSC73yq3dB8tsGohH3F
			hex!["14e59e9d3c8b718545a9fc6994a83eb49f801c38d7cc268ad05dbe281cd5ed63"].into(),
			// 5EkndhZ94fKCnx2zQ2o88rjGGupzhiKraHkEuxhwvDtQDzi5
			hex!["770a5ca4319c336b603afc1561529bb9be2ef91a1d54ab3cc1f3b86ee89525c9"]
				.unchecked_into(),
			// 5FZJsJ3zojt8fqiiR1LE1YtwmGfuVHicLrfBWfQ5ioH5hAsd
			hex!["9a856db37bedb9376c143bf6b033737205a7f04c7e13102fdd902d94d9130c56"]
				.unchecked_into(),
			// 5CDmK3XPvYij5UBeCWXQwrfkboKmAHL3YLfZZeUf2AHHmXsv
			hex!["06e8d69f5e46f672f07ab84387dd81cf7f592ada2153aaab7f1be723bf37bb3b"]
				.unchecked_into(),
			// 5CXJMPeb9xXHgRQYRj9kV3UpvacAc2qNEydrZH9WjyD191kp
			hex!["1448807387ae3a70de2c86ce09a00f7f856344459413027520f48414f6cff972"]
				.unchecked_into(),
		),
		(
			// 5DwWZzE82vNXbLdo8hpnjxrwVSmhBRjVZczQBcyH3Z2oRWKX
			hex!["52fbc068cc0917950befb99cc3f9077d4a2fb0bdaefeaf19a49a88481a11b412"].into(),
			// 5CD3xHo9rp1gGNnnpVgRtVTN55bRHKbaYbDDSr32T9usNLsE
			hex!["065d9d92615eb51aca8d14b06a84d7bf6700f0914095f9c4a8b0e0b62160ea42"].into(),
			// 5FdoJSe3oGSDFU8ebnmQpKr4FUeM9tgtsRMaNWYbT42AzVLV
			hex!["9df22049a7c64c3728f798ec667949930c6835d8f63ef3d47322096ab5e341a1"]
				.unchecked_into(),
			// 5DJ2e2NVmZe2H81MFp3zLQSy1CQmHTmpidB8GCSo3gow2oeh
			hex!["3665a6484210be60c355d1521644c87348f9a0c0c8621d3ea58de3a907508417"]
					.unchecked_into(),
			// 5EFsfWeGvDLmdv6oKmkK9FtieSuTTFzQg8p4bZqxwC5k8q5n
			hex!["60fd2e8b6823646393021617820571411e09260b059203743182d565235aef03"]
				.unchecked_into(),
			// 5EeXANUui1gHckcw7zF3AdmwXyFBzRcicC5wU36CY4cHdNGF
			hex!["7242cf0d47e22380f5d16e4d283cd2fc33d1d7526cb4fbbf9787b564f1ce9679"]
				.unchecked_into(),
		),
		(
			// 5FLc2mJXwzfPsWAtaLAK9f1RUirr3hBRP9btADeYrSY6TSkn
			hex!["90d503d66e6f555429433573bf0998f60e4916b3e80f16fed334f11470533d4b"].into(),
			// 5CXuG9z2XcHwdqTAG451tNvcr9PSrVfEXtCkzkRwPnFLBE7Y
			hex!["14be04b5670df7ca712ce3e67d620fd0846f87fa34de72bb2f80c9f0c881b401"].into(),
			// 5DZ4Sq7C6fDPRgm4im5H6wyhL3SbUqCWAfRB9gMc1hFAgHrb
			hex!["41dc69dafec1016f5d4168975a6c7615017703f6d8b5fdeeca4952ed91fabf67"]
				.unchecked_into(),
			// 5FWy2dvHo4B2CnkwumMQgM5hVUV3mgviB16WQ1DWqFcZM8bi
			hex!["98bc276917d57ead1874841aa956f9fa28a8c9a21a3f03eb982186fead6a2467"]
				.unchecked_into(),
			// 5FvBb7ZaSny6h8G9HCdKEZH79o7BfjVxKjsfMNc7vgoMFZ3f
			hex!["aa71142ae23a5c60f33a064462c44c5425c48c7345f12dc9ad00a56580e8835b"]
				.unchecked_into(),
			// 5ELz6TfwTwbwAsXoEycB5oTQCcMPLipEqDRsjVw7GYot2pNh
			hex!["64e30dfddf0e622b1db1e6ad27f3724b349ed9369862b84ec9a1a262c724603e"]
				.unchecked_into(),
		),
	];

    let root_key: AccountId = hex!["4e5c769d0007d4da9603f7be2afff9abdc944fec97d7da7c19efc8b7150b524b"]
    .into();

    devnet_genesis(initial_authorities, vec![], root_key)
}

pub fn staging_testnet_config_genesis() -> GenesisConfig {
    #[rustfmt::skip]
	// stash, controller, session-key
	// generated with secret:
	// for i in 1 2 3 4 ; do for j in stash controller; do subkey inspect "$secret"/fir/$j/$i; done; done
	//
	// and
	//
	// for i in 1 2 3 4 ; do for j in session; do subkey --ed25519 inspect "$secret"//fir//$j//$i; done; done

	let initial_authorities: Vec<(
		AccountId,
		AccountId,
		GrandpaId,
		BabeId,
		ImOnlineId,
		AuthorityDiscoveryId,
	)> = vec![
		(
			// 5Fbsd6WXDGiLTxunqeK5BATNiocfCqu9bS1yArVjCgeBLkVy
			hex!["9c7a2ee14e565db0c69f78c7b4cd839fbf52b607d867e9e9c5a79042898a0d12"].into(),
			// 5EnCiV7wSHeNhjW3FSUwiJNkcc2SBkPLn5Nj93FmbLtBjQUq
			hex!["781ead1e2fa9ccb74b44c19d29cb2a7a4b5be3972927ae98cd3877523976a276"].into(),
			// 5Fb9ayurnxnaXj56CjmyQLBiadfRCqUbL2VWNbbe1nZU6wiC
			hex!["9becad03e6dcac03cee07edebca5475314861492cdfc96a2144a67bbe9699332"]
				.unchecked_into(),
			// 5EZaeQ8djPcq9pheJUhgerXQZt9YaHnMJpiHMRhwQeinqUW8
			hex!["6e7e4eb42cbd2e0ab4cae8708ce5509580b8c04d11f6758dbf686d50fe9f9106"]
				.unchecked_into(),
			// 5EZaeQ8djPcq9pheJUhgerXQZt9YaHnMJpiHMRhwQeinqUW8
			hex!["6e7e4eb42cbd2e0ab4cae8708ce5509580b8c04d11f6758dbf686d50fe9f9106"]
				.unchecked_into(),
			// 5EZaeQ8djPcq9pheJUhgerXQZt9YaHnMJpiHMRhwQeinqUW8
			hex!["6e7e4eb42cbd2e0ab4cae8708ce5509580b8c04d11f6758dbf686d50fe9f9106"]
				.unchecked_into(),
		),
		(
			// 5ERawXCzCWkjVq3xz1W5KGNtVx2VdefvZ62Bw1FEuZW4Vny2
			hex!["68655684472b743e456907b398d3a44c113f189e56d1bbfd55e889e295dfde78"].into(),
			// 5Gc4vr42hH1uDZc93Nayk5G7i687bAQdHHc9unLuyeawHipF
			hex!["c8dc79e36b29395413399edaec3e20fcca7205fb19776ed8ddb25d6f427ec40e"].into(),
			// 5EockCXN6YkiNCDjpqqnbcqd4ad35nU4RmA1ikM4YeRN4WcE
			hex!["7932cff431e748892fa48e10c63c17d30f80ca42e4de3921e641249cd7fa3c2f"]
				.unchecked_into(),
			// 5DhLtiaQd1L1LU9jaNeeu9HJkP6eyg3BwXA7iNMzKm7qqruQ
			hex!["482dbd7297a39fa145c570552249c2ca9dd47e281f0c500c971b59c9dcdcd82e"]
				.unchecked_into(),
			// 5DhLtiaQd1L1LU9jaNeeu9HJkP6eyg3BwXA7iNMzKm7qqruQ
			hex!["482dbd7297a39fa145c570552249c2ca9dd47e281f0c500c971b59c9dcdcd82e"]
				.unchecked_into(),
			// 5DhLtiaQd1L1LU9jaNeeu9HJkP6eyg3BwXA7iNMzKm7qqruQ
			hex!["482dbd7297a39fa145c570552249c2ca9dd47e281f0c500c971b59c9dcdcd82e"]
				.unchecked_into(),
		),
		(
			// 5DyVtKWPidondEu8iHZgi6Ffv9yrJJ1NDNLom3X9cTDi98qp
			hex!["547ff0ab649283a7ae01dbc2eb73932eba2fb09075e9485ff369082a2ff38d65"].into(),
			// 5FeD54vGVNpFX3PndHPXJ2MDakc462vBCD5mgtWRnWYCpZU9
			hex!["9e42241d7cd91d001773b0b616d523dd80e13c6c2cab860b1234ef1b9ffc1526"].into(),
			// 5E1jLYfLdUQKrFrtqoKgFrRvxM3oQPMbf6DfcsrugZZ5Bn8d
			hex!["5633b70b80a6c8bb16270f82cca6d56b27ed7b76c8fd5af2986a25a4788ce440"]
				.unchecked_into(),
			// 5DhKqkHRkndJu8vq7pi2Q5S3DfftWJHGxbEUNH43b46qNspH
			hex!["482a3389a6cf42d8ed83888cfd920fec738ea30f97e44699ada7323f08c3380a"]
				.unchecked_into(),
			// 5DhKqkHRkndJu8vq7pi2Q5S3DfftWJHGxbEUNH43b46qNspH
			hex!["482a3389a6cf42d8ed83888cfd920fec738ea30f97e44699ada7323f08c3380a"]
				.unchecked_into(),
			// 5DhKqkHRkndJu8vq7pi2Q5S3DfftWJHGxbEUNH43b46qNspH
			hex!["482a3389a6cf42d8ed83888cfd920fec738ea30f97e44699ada7323f08c3380a"]
				.unchecked_into(),
		),
		(
			// 5HYZnKWe5FVZQ33ZRJK1rG3WaLMztxWrrNDb1JRwaHHVWyP9
			hex!["f26cdb14b5aec7b2789fd5ca80f979cef3761897ae1f37ffb3e154cbcc1c2663"].into(),
			// 5EPQdAQ39WQNLCRjWsCk5jErsCitHiY5ZmjfWzzbXDoAoYbn
			hex!["66bc1e5d275da50b72b15de072a2468a5ad414919ca9054d2695767cf650012f"].into(),
			// 5DMa31Hd5u1dwoRKgC4uvqyrdK45RHv3CpwvpUC1EzuwDit4
			hex!["3919132b851ef0fd2dae42a7e734fe547af5a6b809006100f48944d7fae8e8ef"]
				.unchecked_into(),
			// 5C4vDQxA8LTck2xJEy4Yg1hM9qjDt4LvTQaMo4Y8ne43aU6x
			hex!["00299981a2b92f878baaf5dbeba5c18d4e70f2a1fcd9c61b32ea18daf38f4378"]
				.unchecked_into(),
			// 5C4vDQxA8LTck2xJEy4Yg1hM9qjDt4LvTQaMo4Y8ne43aU6x
			hex!["00299981a2b92f878baaf5dbeba5c18d4e70f2a1fcd9c61b32ea18daf38f4378"]
				.unchecked_into(),
			// 5C4vDQxA8LTck2xJEy4Yg1hM9qjDt4LvTQaMo4Y8ne43aU6x
			hex!["00299981a2b92f878baaf5dbeba5c18d4e70f2a1fcd9c61b32ea18daf38f4378"]
				.unchecked_into(),
		),
	];

    // generated with secret: subkey inspect "$secret"/fir
    let root_key: AccountId = hex![
        // 5Ff3iXP75ruzroPWRP2FYBHWnmGGBSb63857BgnzCoXNxfPo
        "9ee5e5bdc0ec239eb164f865ecc345ce4c88e76ee002e0f7e318097347471809"
    ]
    .into();

    testnet_genesis(initial_authorities, vec![], root_key)
}


pub fn development_config_genesis() -> GenesisConfig {
    testnet_genesis(
        vec![authority_keys_from_seed("Alice"), authority_keys_from_seed("Bob")],
        vec![],
        get_account_id_from_seed::<sr25519::Public>("Alice"),
    )
}
