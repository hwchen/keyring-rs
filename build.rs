extern crate skeptic;

fn main() {
    // generate doc tests for `README.md`
    // (I set them all to no_run, to just check for compilation)
    skeptic::generate_doc_tests(&["README.md"]);
}
