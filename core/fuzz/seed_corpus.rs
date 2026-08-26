// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0
//
// Writes the seed corpus (valid inputs minted by the crate's own
// serializers, see core/src/fuzz_smoke.rs) into fuzz/corpus/<target>/ so
// libFuzzer starts from accepted inputs rather than from nothing.
//
//   cargo run --bin seed_corpus            (from core/fuzz/)
//
// The audit QR vector pages (v105_dup_hint_vectors.html,
// value_range_vectors.html) are the other corpus source once they have a
// home in the tree: drop their payload bytes into the matching directory.

use std::fs;
use std::path::Path;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    for (target, seeds) in kassigner_core::fuzz_smoke::seed_corpus() {
        let dir = root.join(target);
        fs::create_dir_all(&dir).expect("corpus dir");
        for (i, s) in seeds.iter().enumerate() {
            fs::write(dir.join(format!("seed_{i:02}")), s).expect("seed file");
        }
        println!("{target}: {} seeds -> {}", seeds.len(), dir.display());
    }
}
