# NOTE: Use only for testing.
# Starts up a development threshold signing server using
# the development password for the kvdb.
export ROCKET_PORT=3002
rm -rf .entropy/production/db/bob
./target/release/server --bob
