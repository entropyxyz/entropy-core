# Builds a JS Module for nodejs with glue for the compiled WASM.
build-nodejs ::
	wasm-pack build --target nodejs --scope "entropyxyz" . --no-default-features -F full-client-wasm
	# cp js-README.md ./pkg/README.md
	cp ../../LICENSE ./pkg/

# Builds a JS Module for web with glue for the compiled WASM.
build-web ::
	wasm-pack build --target web --scope "entropyxyz" . --no-default-features -F full-client-wasm
	# cp js-README.md ./pkg/README.md
	cp ../../LICENSE ./pkg/

# Another build option for compiling to webpack, builds a typescript library around the WASM for use
# with npm.
build-bundler ::
	wasm-pack build --target bundler --scope "entropyxyz" . --no-default-features -F full-client-wasm
	# cp js-README.md ./pkg/README.md
	cp ../../LICENSE ./pkg/

# Cleans out build artifacts.
clean ::
	rm -rf pkg/ nodejs-test/node_modules/
