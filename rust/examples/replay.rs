//! Differential testing helper: replays a vectors file (same format as
//! tests/golden/vectors.json, `expected` optional) through the Rust kernel and
//! prints one JSON line per vector: {"i": index, "got": DecisionRecord} or
//! {"i": index, "panic": message}. The Python side compares.
use gravit_verifier_rs::{verify, Epistemic, Evidence, Registry, TrustRoot};
use serde_json::{json, Value};
use std::{env, fs, panic, path::PathBuf};

fn golden_path(name: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "..", "tests", "golden", name].iter().collect()
}

fn main() {
    let path = env::args().nth(1).expect("usage: replay <vectors.json>");
    let bindings: Value = serde_json::from_str(&fs::read_to_string(golden_path("bindings.json")).unwrap()).unwrap();
    let bindings = bindings.as_array().unwrap().clone();
    let root = TrustRoot::from_bytes(&fs::read(golden_path("trust_root.json")).unwrap()).unwrap();
    let sigs = fs::read_to_string(golden_path("registry.json.sig")).unwrap();
    let registry = Registry::from_bytes(&fs::read(golden_path("registry.json")).unwrap(), &sigs, &root).unwrap();
    let vectors: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    panic::set_hook(Box::new(|_| {}));
    for (i, v) in vectors.as_array().unwrap().iter().enumerate() {
        let r = panic::catch_unwind(|| {
            let name = v["name"].as_str().unwrap();
            let claimed = v["claimed_state"].as_str().map(|s| Epistemic::from_name(s).expect("known state"));
            let evidence: Vec<Evidence> = v["evidence"].as_array().unwrap().iter().map(Evidence::from_value).collect();
            let reg = if v["use_registry"].as_bool().unwrap() { Some(&registry) } else { None };
            verify(&bindings, name, claimed, &evidence, &v["context"], reg)
        });
        let line = match r {
            Ok(got) => json!({"i": i, "got": got}),
            Err(e) => json!({"i": i, "panic": e.downcast_ref::<String>().cloned().or(e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()}),
        };
        println!("{}", line);
    }
}
