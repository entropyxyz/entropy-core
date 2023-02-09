# NOTE: Use only for testing.
# Starts up a development threshold signing server using
# the development password for the kvdb.
rm -rf .entropy/production/db/kvstore
./target/release/server --alice
