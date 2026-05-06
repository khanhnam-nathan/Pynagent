//! Scanner Benchmark
//!
//! Benchmarks for the Pynagent Rust scanner components.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;

use Pynagent_rs::parse;

const SMALL_CODE: &str = r#"
def process():
    x = 1
    return x
"#;

const MEDIUM_CODE: &str = r#"
import os
import sys
import json

def initialize_app():
    config_path = "/etc/myapp/config.json"
    return config_path

def process_request(user_input):
    if user_input is not None:
        print(f"Processing: {user_input}")
    return True

def validate_data(data):
    if data is not None:
        return True
    return False

def calculate(x, y):
    if x is 200:
        return x + y
    return x - y
"#;

const LARGE_CODE: &str = r#"
import os
import sys
import json
import yaml
import pickle
import hashlib

class DataProcessor:
    def __init__(self, config_path):
        self.config_path = config_path
        self.results = []

    def load_config(self):
        with open(self.config_path, "r") as f:
            return json.load(f)

    def process(self, data):
        for item in data:
            if item.get("active"):
                self.results.append(item)

    def save_results(self, path):
        with open(path, "w") as f:
            json.dump(self.results, f)

def execute_command(cmd):
    os.system(cmd)
    return "Done"

def hash_password(password):
    return hashlib.md5(password.encode())

class UserManager:
    def __init__(self):
        self.users = []

    def add_user(self, name, email):
        user = {"name": name, "email": email}
        self.users.append(user)
        return user

    def find_user(self, email):
        for user in self.users:
            if user["email"] == email:
                return user
        return None
"#;

// --------------------------------------------------------------------------
// File Size Benchmarks
// --------------------------------------------------------------------------

fn bench_parse_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_by_size");

    group.bench_function("small_10_lines", |b| {
        b.iter(|| {
            let _ = parse(black_box(SMALL_CODE));
        });
    });

    group.bench_function("medium_50_lines", |b| {
        b.iter(|| {
            let _ = parse(black_box(MEDIUM_CODE));
        });
    });

    group.bench_function("large_200_lines", |b| {
        b.iter(|| {
            let _ = parse(black_box(LARGE_CODE));
        });
    });

    group.finish();
}

// --------------------------------------------------------------------------
// Throughput Benchmarks
// --------------------------------------------------------------------------

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.throughput(criterion::Throughput::Bytes(MEDIUM_CODE.len() as u64));

    group.bench_function("mb_per_second", |b| {
        b.iter(|| {
            let _ = parse(black_box(MEDIUM_CODE));
        });
    });

    group.finish();
}

// --------------------------------------------------------------------------
// Batch Scan (Item 4a: Real-World Simulation)
// --------------------------------------------------------------------------

/// Benchmark scanning multiple files (simulates real-world project scanning).
/// Uses repeated code samples to simulate ~200 files of mixed sizes.
fn bench_batch_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_scan");

    // Simulate scanning 200 files: mix of small, medium, and large files
    let files: Vec<&str> = (0..200)
        .map(|i| match i % 3 {
            0 => SMALL_CODE,
            1 => MEDIUM_CODE,
            _ => LARGE_CODE,
        })
        .collect();

    group.bench_function("scan_200_files", |b| {
        b.iter(|| {
            for code in &files {
                let _ = parse(black_box(*code));
            }
        });
    });

    group.throughput(criterion::Throughput::Elements(200));
    group.finish();
}

// --------------------------------------------------------------------------
// Full Pipeline Benchmark
// --------------------------------------------------------------------------

/// Benchmark the full rule evaluation pipeline (parse + all rules).
fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_pipeline");

    let tree = parse(LARGE_CODE).expect("Should parse");
    let rules = Pynagent_rs::rules::security::all_security_rules();

    group.bench_function("parse_and_scan_large", |b| {
        b.iter(|| {
            let mut findings_count = 0;
            for rule in &rules {
                findings_count += rule.detect(black_box(&tree), LARGE_CODE).len();
            }
            black_box(findings_count);
        });
    });

    group.throughput(criterion::Throughput::Bytes(LARGE_CODE.len() as u64));
    group.finish();
}

// --------------------------------------------------------------------------
// Criterion Group
// --------------------------------------------------------------------------

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(5))
        .warm_up_time(Duration::from_secs(1))
        .sample_size(50);
    targets =
        bench_parse_sizes,
        bench_throughput,
        bench_batch_scan,
        bench_full_pipeline,
}
criterion_main!(benches);
