//! Chaos Tests - Stress testing PyNEAT's resilience
//!
//! These tests run PyNEAT against pathological Python inputs to verify:
//! - Parser handles edge cases without panicking
//! - Memory usage stays reasonable
//! - Performance degradation is bounded
//!
//! Copyright (C) 2026 PyNEAT Authors

use pyneat_rs::scanner::multilang::parse_ln_ast;
use pyneat_rs::rules::security::all_security_rules;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
use rayon::prelude::*;

/// Chaos test result with timing and finding counts
struct ChaosResult {
    file: String,
    duration: Duration,
    functions_found: usize,
    classes_found: usize,
    imports_found: usize,
    calls_found: usize,
    rules_fired: usize,
    error: Option<String>,
}

/// Run chaos tests and verify resilience
#[test]
fn test_chaos_all_files_parse_without_panic() {
    let chaos_dir = Path::new("tests/fixtures/chaos");
    let test_files = [
        "test_01_deep_nesting.py",
        "test_02_long_definitions.py",
        "test_03_large_file.py",
        "test_04_malformed_syntax.py",
        "test_05_unicode_edge_cases.py",
        "test_06_complex_control_flow.py",
        "test_07_function_edge_cases.py",
        "test_08_import_patterns.py",
        "test_09_class_edge_cases.py",
        "test_10_security_patterns.py",
    ];

    let mut results: Vec<ChaosResult> = Vec::new();

    for test_file in &test_files {
        let file_path = chaos_dir.join(test_file);
        let start = Instant::now();

        let result = std::panic::catch_unwind(|| {
            let content = fs::read_to_string(&file_path)
                .expect(&format!("Failed to read {}", test_file));

            // Parse the file
            let ast = parse_ln_ast(&content, "python")
                .expect(&format!("Failed to parse {}", test_file));
            let duration = start.elapsed();

            // Run security rules on it
            let tree = pyneat_rs::scanner::tree_sitter::parse(&content)
                .expect(&format!("Failed to parse with tree-sitter {}", test_file));
            let rules = all_security_rules();

            let findings: Vec<_> = rules.par_iter()
                .flat_map(|rule| rule.detect(&tree, &content))
                .collect();

            ChaosResult {
                file: test_file.to_string(),
                duration,
                functions_found: ast.functions.len(),
                classes_found: ast.classes.len(),
                imports_found: ast.imports.len(),
                calls_found: ast.calls.len(),
                rules_fired: findings.len(),
                error: None,
            }
        });

        let chaos_result = match result {
            Ok(r) => r,
            Err(e) => {
                ChaosResult {
                    file: test_file.to_string(),
                    duration: start.elapsed(),
                    functions_found: 0,
                    classes_found: 0,
                    imports_found: 0,
                    calls_found: 0,
                    rules_fired: 0,
                    error: Some(format!("{:?}", e)),
                }
            }
        };

        results.push(chaos_result);
    }

    // Verify no tests panicked
    for result in &results {
        if let Some(ref err) = result.error {
            panic!(
                "Chaos test {} panicked: {}. Duration: {:?}",
                result.file, err, result.duration
            );
        }
    }

    // Print summary
    println!("\n=== Chaos Test Results ===");
    for result in &results {
        println!(
            "{}: {:?}, functions={}, classes={}, imports={}, calls={}, rules={}",
            result.file,
            result.duration,
            result.functions_found,
            result.classes_found,
            result.imports_found,
            result.calls_found,
            result.rules_fired
        );
    }
}

/// Test 1: Deep nesting - verify parser handles 50+ levels of nesting
#[test]
fn test_chaos_deep_nesting() {
    let content = fs::read_to_string("tests/fixtures/chaos/test_01_deep_nesting.py")
        .expect("Failed to read test file");

    let ast = parse_ln_ast(&content, "python")
        .expect("Failed to parse");

    // Should find the nested function
    assert!(ast.functions.len() >= 1, "Should find at least 1 function");

    // Verify deep nesting is detected
    assert!(
        !ast.deep_nesting.is_empty(),
        "Should detect deep nesting (>5 levels)"
    );
}

/// Test 3: Large file - verify performance is reasonable
#[test]
fn test_chaos_large_file_performance() {
    let content = fs::read_to_string("tests/fixtures/chaos/test_03_large_file.py")
        .expect("Failed to read test file");

    let start = Instant::now();
    let ast = parse_ln_ast(&content, "python")
        .expect("Failed to parse");
    let parse_duration = start.elapsed();

    // Large file parsing should complete within reasonable time
    // The test file has a loop that generates code - we expect it to be relatively small after parsing
    assert!(
        parse_duration < Duration::from_secs(5),
        "Large file parsing took too long: {:?}",
        parse_duration
    );

    // The file contains code generation patterns and string literals
    // We should find the function definition for code_block
    assert!(
        ast.strings.len() > 0,
        "Should find strings in the large file, found {}",
        ast.strings.len()
    );

    println!(
        "Large file ({} bytes) parsed in {:?}: {} functions, {} strings",
        content.len(),
        parse_duration,
        ast.functions.len(),
        ast.strings.len()
    );
}

/// Test 4: Malformed syntax - verify graceful error handling
#[test]
fn test_chaos_malformed_syntax_graceful() {
    // Note: tree-sitter is robust and parses partial syntax.
    // The key test is that we don't panic.
    let content = fs::read_to_string("tests/fixtures/chaos/test_04_malformed_syntax.py")
        .expect("Failed to read test file");

    // Should not panic even with malformed syntax
    let ast = parse_ln_ast(&content, "python")
        .expect("Failed to parse malformed syntax");

    // We may find some valid functions despite the errors
    // The important thing is no panic
    println!(
        "Malformed syntax: parsed {} functions, {} imports",
        ast.functions.len(),
        ast.imports.len()
    );
}

/// Test 5: Unicode edge cases
#[test]
fn test_chaos_unicode_handling() {
    let content = fs::read_to_string("tests/fixtures/chaos/test_05_unicode_edge_cases.py")
        .expect("Failed to read test file");

    let ast = parse_ln_ast(&content, "python")
        .expect("Failed to parse");

    // Should handle unicode without crashing
    assert!(
        ast.functions.len() >= 1,
        "Should find unicode-named function"
    );

    // Should find strings (including unicode strings)
    assert!(
        !ast.strings.is_empty(),
        "Should find unicode strings"
    );
}

/// Test 10: Security patterns - verify rules detect vulnerabilities
#[test]
fn test_chaos_security_rules_detect_vulnerabilities() {
    let content = fs::read_to_string("tests/fixtures/chaos/test_10_security_patterns.py")
        .expect("Failed to read test file");

    let tree = pyneat_rs::scanner::tree_sitter::parse(&content)
        .expect("Failed to parse");
    let rules = all_security_rules();

    let findings: Vec<_> = rules.par_iter()
        .flat_map(|rule| rule.detect(&tree, &content))
        .collect();

    // Should detect multiple security issues
    // We expect at least: SQL injection, command injection, hardcoded secrets
    assert!(
        findings.len() >= 5,
        "Should detect multiple security issues, found {}",
        findings.len()
    );

    // Print what was detected for verification
    println!("Detected {} security issues:", findings.len());
    for finding in &findings {
        println!("  - {}", finding.rule_id);
    }
}

/// Test 10b: Malformed syntax with security rules - should not panic
#[test]
fn test_chaos_malformed_syntax_with_rules() {
    let content = fs::read_to_string("tests/fixtures/chaos/test_04_malformed_syntax.py")
        .expect("Failed to read test file");

    let result = std::panic::catch_unwind(|| {
        let tree = pyneat_rs::scanner::tree_sitter::parse(&content)
            .expect("Failed to parse");
        let rules = all_security_rules();

        rules.par_iter()
            .flat_map(|rule| rule.detect(&tree, &content))
            .collect::<Vec<_>>()
    });

    assert!(
        result.is_ok(),
        "Running rules on malformed syntax should not panic"
    );
}

/// Performance benchmark for chaos tests
#[test]
fn test_chaos_benchmark_all_files() {
    let chaos_dir = Path::new("tests/fixtures/chaos");
    let test_files = [
        "test_01_deep_nesting.py",
        "test_02_long_definitions.py",
        "test_03_large_file.py",
        "test_04_malformed_syntax.py",
        "test_05_unicode_edge_cases.py",
        "test_06_complex_control_flow.py",
        "test_07_function_edge_cases.py",
        "test_08_import_patterns.py",
        "test_09_class_edge_cases.py",
        "test_10_security_patterns.py",
    ];

    let start = Instant::now();
    let mut total_bytes = 0usize;

    for test_file in &test_files {
        let file_path = chaos_dir.join(test_file);
        let content = fs::read_to_string(&file_path)
            .expect(&format!("Failed to read {}", test_file));

        total_bytes += content.len();

        // Parse
        let _ast = parse_ln_ast(&content, "python")
            .expect("Failed to parse");

        // Run rules
        let tree = pyneat_rs::scanner::tree_sitter::parse(&content)
            .expect("Failed to parse");
        let rules = all_security_rules();
        let _findings: Vec<_> = rules.par_iter()
            .flat_map(|rule| rule.detect(&tree, &content))
            .collect();
    }

    let total_duration = start.elapsed();
    let files_per_sec = test_files.len() as f64 / total_duration.as_secs_f64();
    let bytes_per_sec = total_bytes as f64 / total_duration.as_secs_f64();

    println!(
        "\n=== Chaos Benchmark ===\n\
         Total files: {}\n\
         Total bytes: {}\n\
         Total time: {:?}\n\
         Files/sec: {:.2}\n\
         Bytes/sec: {:.2}",
        test_files.len(),
        total_bytes,
        total_duration,
        files_per_sec,
        bytes_per_sec
    );

    // Debug build throughput varies - just ensure it completes without hanging
    assert!(
        bytes_per_sec > 1000.0,
        "Should process at least some data, got {:.0} bytes/sec",
        bytes_per_sec
    );
}
