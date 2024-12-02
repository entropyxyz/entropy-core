use entropy_testing_utils::test_node_process_testing_state;
use std::io;

#[tokio::main]
async fn main() {
    let _ctx = test_node_process_testing_state(true).await;

    let mut buffer = String::new();
    let stdin = io::stdin();
    stdin.read_line(&mut buffer).unwrap();
}
