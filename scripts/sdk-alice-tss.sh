# NOTE: Use only for testing.
# Starts up a development threshold signing server using
# the development password for the kvdb.
rm -rf kvstore
echo tofnd_unsafe_password | ./target/release/server --alice
