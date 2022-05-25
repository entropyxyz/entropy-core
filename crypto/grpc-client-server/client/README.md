# Entropy minimal client-server for returning signing party over gRPC

What's broken:

- hard-coded IP addresses in the .env file
- hard-coded signing party IP addresses

## To run

Clone me and [the gRPC repo](https://github.com/thor314/signing-grpc) into adjacent directories. Build and run. IP addresses may require configuration.

```sh
cargo run --bin client
# in another term
cargo run --bin server
```
