extern crate vergen;
use vergen::*;
fn main() {
    vergen(SEMVER | COMMIT_DATE).unwrap();
}
