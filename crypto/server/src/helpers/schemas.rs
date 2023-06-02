//! Generate JSON-schema files for common types used in HTTP requests
use schemars::schema_for;

use crate::user::api::{GenericTransactionRequest, UserTransactionRequest};

/// Write the schemas to files locally
pub fn generate_json_schemas() {
    println!("Generating schemas...");

    let schema = schema_for!(UserTransactionRequest);
    let output = serde_json::to_string_pretty(&schema).expect("cannot serialize json schema");
    std::fs::write("UserTransactionRequest.json", output)
        .expect("cannot write json schema to file");

    let schema = schema_for!(GenericTransactionRequest);
    let output = serde_json::to_string_pretty(&schema).expect("cannot serialize json schema");
    std::fs::write("GenericTransactionRequest.json", output)
        .expect("cannot write json schema to file");

    println!("done");
}
