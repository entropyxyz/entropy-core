# Builds a JS Module for nodejs with glue for the compiled WASM.
build-nodejs ::
	wasm-pack build --target nodejs . --no-default-features -F wasm

# Builds a JS Module for web with glue for the compiled WASM.
build-web ::
	wasm-pack build --target web . --no-default-features -F wasm

# Another build option for compiling to webpack, builds a typescript library around the WASM for use
# with npm.
build-bundler ::
	wasm-pack build --target bundler . --no-default-features -F wasm

# Builds a JS Module for nodejs with testing features
build-nodejs-testing ::
	wasm-pack build --target nodejs . --no-default-features -F wasm-test

# Cleans out build artifacts.
clean ::
	rm -rf pkg/ nodejs-test/node_modules/
