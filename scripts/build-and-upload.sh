readonly ARCH=${1:-""}
readonly tag="$(git tag|head -n 1)-$(git rev-parse --short HEAD)"
readonly fn="$ARCH-$tag"
if [ ${#ARCH} -eq 0 ]; then echo "script needs arg" && exit 1; fi
cargo build --target $ARCH --release 
cp -r target/release $fn
tar cf $fn.tar.xz $fn
_url="$(echo curl -sS -F\'file=@$ARCH.tar.xz\' 'https://entropy.family/u' | bash)"
echo $_url