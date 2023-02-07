source $HOME/.cargo/env
. $HOME/.cargo/env
readonly ARCH=${1:-""}
if [ ${#ARCH} -eq 0 ]; then echo "script needs arg" && exit 1; fi
readonly tag="$(git tag|head -n 1)-$(git rev-parse --short HEAD)"
readonly fn="$ARCH-$tag"
readonly tar="entropy-$fn.tar.zst"
rustup show
rustup target add $ARCH
rustup target add wasm32-unknown-unknown
cargo build -p entropy --release
cargo build -p server --target $ARCH --release
touch $tar
mkdir -p $fn
mv 'target/release/entropy' 'target/release/server' $fn
tar -acvf "$tar" "$fn"
echo curl -sS -F\'file=@$tar\' 'https://entropy.family/u' | bash
