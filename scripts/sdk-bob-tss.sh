# NOTE: Use only for testing.
# Starts up a development threshold signing server using
# the development password for the kvdb.
rm -rf .entropy/production/db/bob
./target/release/server --bob --threshold-url="127.0.0.1:3002"
