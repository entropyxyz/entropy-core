readonly ARCH=${1:-""}
if [ ${#ARCH} -eq 0 ]; then echo "script needs arg" && exit 1; fi
cargo build --target $ARCH --release 
mv target/release $ARCH
tar cf $ARCH.tar.xz $ARCH
_url="$(echo curl -sS -F\'file=@$ARCH.tar.xz\' 'https://entropy.family/u' | bash)"
echo $_url