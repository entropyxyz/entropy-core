# this script copies the entropy and server release binaries to the testing location in entropy-js, assuming entropy-core and entropy-js are in the same folder

cp target/release/entropy ../entropy-js/testing-utils/test-binaries/
cp target/release/server ../entropy-js/testing-utils/test-binaries/
