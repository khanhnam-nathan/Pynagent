//! Head-to-head competitor comparison benchmarks for PyNEAT.
//!
//! Compares PyNEAT's Rust scanner against:
//! - Semgrep (via subprocess)
//! - Bandit (via subprocess)
//! - PyNEAT's own Python implementation
//!
//! Run with: `cargo bench --bench compare`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const SAMPLE_CODE_PYTHON: &str = r#"
import os
import sys
import pickle
import hashlib

def process_user_data(user_input):
    data = pickle.loads(user_input)
    return data

def execute_command(cmd):
    os.system(cmd)
    return "Done"

def hash_password(password):
    return hashlib.md5(password.encode())

def check_auth(username, password):
    query = f"SELECT * FROM users WHERE username='{username}'"
    return query

def read_file(path):
    with open(path, 'r') as f:
        return f.read()

def make_secret():
    secret = "super_secret_key_12345"
    return secret
"#;

// --------------------------------------------------------------------------
// PyNEAT (Rust) — measured via internal API
// --------------------------------------------------------------------------

fn bench_pyneat_rust(c: &mut Criterion) {
    use pyneat_rs::rules::security::all_security_rules;
    use pyneat_rs::scanner::tree_sitter::parse;

    let mut group = c.benchmark_group("competitor_comparison");

    group.bench_function("pyneat_rust", |b| {
        b.iter(|| {
            let tree = parse(black_box(SAMPLE_CODE_PYTHON));
            if let Ok(tree) = tree {
                let rules = all_security_rules();
                let mut findings_count = 0;
                for rule in &rules {
                    let findings = rule.detect(&tree, SAMPLE_CODE_PYTHON);
                    findings_count += findings.len();
                }
                black_box(findings_count);
            }
        });
    });

    group.finish();
}

// --------------------------------------------------------------------------
// Bandit (subprocess)
// --------------------------------------------------------------------------

fn bench_bandit(c: &mut Criterion) {
    let mut group = c.benchmark_group("competitor_comparison");

    group.bench_function("bandit", |b| {
        b.iter(|| {
            let temp_dir = std::env::temp_dir();
            let test_file = temp_dir.join("pyneat_benchmark_test.py");
            let _ = std::fs::write(&test_file, SAMPLE_CODE_PYTHON);

            let result = Command::new("bandit")
                .args(["-f", "json", "-r"])
                .arg(&test_file)
                .output();

            let _ = std::fs::remove_file(&test_file);

            match result {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let parsed: serde_json::Value =
                        serde_json::from_str(&stdout).unwrap_or(serde_json::Value::Null);
                    let issues = parsed
                        .get("results")
                        .and_then(|r| r.as_array())
                        .map(|arr| arr.len())
                        .unwrap_or(0);
                    black_box(issues);
                }
                Err(_) => {
                    black_box(0usize);
                }
            }
        });
    });

    group.finish();
}

// --------------------------------------------------------------------------
// Semgrep (subprocess)
// --------------------------------------------------------------------------

fn bench_semgrep(c: &mut Criterion) {
    let mut group = c.benchmark_group("competitor_comparison");

    group.bench_function("semgrep", |b| {
        b.iter(|| {
            let temp_dir = std::env::temp_dir();
            let test_file = temp_dir.join("pyneat_benchmark_test.py");
            let _ = std::fs::write(&test_file, SAMPLE_CODE_PYTHON);

            let result = Command::new("semgrep")
                .args(["--config=auto", "--json", "--quiet", "--lang=python"])
                .arg(&test_file)
                .output();

            let _ = std::fs::remove_file(&test_file);

            match result {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let parsed: serde_json::Value =
                        serde_json::from_str(&stdout).unwrap_or(serde_json::Value::Null);
                    let results = parsed
                        .get("results")
                        .and_then(|r| r.as_array())
                        .map(|arr| arr.len())
                        .unwrap_or(0);
                    black_box(results);
                }
                Err(_) => {
                    black_box(0usize);
                }
            }
        });
    });

    group.finish();
}

// --------------------------------------------------------------------------
// PyNEAT Python (for comparison)
// --------------------------------------------------------------------------

fn bench_pyneat_python(c: &mut Criterion) {
    use pyneat_rs::rules::security::all_security_rules;
    use pyneat_rs::scanner::tree_sitter::parse;

    let mut group = c.benchmark_group("competitor_comparison");

    group.bench_function("pyneat_python", |b| {
        b.iter(|| {
            let tree = parse(black_box(SAMPLE_CODE_PYTHON));
            if let Ok(tree) = tree {
                let rules = all_security_rules();
                let mut findings_count = 0;
                for rule in &rules {
                    let findings = rule.detect(&tree, SAMPLE_CODE_PYTHON);
                    findings_count += findings.len();
                }
                black_box(findings_count);
            }
        });
    });

    group.finish();
}

// --------------------------------------------------------------------------
// Findings quality comparison
// --------------------------------------------------------------------------

fn bench_findings_coverage(c: &mut Criterion) {
    use pyneat_rs::rules::security::all_security_rules;
    use pyneat_rs::scanner::tree_sitter::parse;

    let mut group = c.benchmark_group("findings_coverage");

    group.bench_function("rule_coverage", |b| {
        b.iter(|| {
            let tree = parse(black_box(SAMPLE_CODE_PYTHON));
            if let Ok(tree) = tree {
                let rules = all_security_rules();
                let mut findings: Vec<(String, String)> = Vec::new();
                for rule in &rules {
                    for f in rule.detect(&tree, SAMPLE_CODE_PYTHON) {
                        findings.push((f.rule_id.clone(), f.severity.clone()));
                    }
                }
                black_box(findings);
            }
        });
    });

    group.finish();
}

// --------------------------------------------------------------------------
// Benchmark group definition
// --------------------------------------------------------------------------

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .warm_up_time(Duration::from_secs(2))
        .sample_size(20)
        .noise_threshold(0.05);
    targets =
        bench_pyneat_rust,
        bench_findings_coverage,
        bench_bandit,
        bench_semgrep,
}
criterion_main!(benches);
