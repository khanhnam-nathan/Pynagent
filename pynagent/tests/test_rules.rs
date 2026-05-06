//! Pynagent Rust Security Scanner
//!
//! Copyright (C) 2026 Pynagent Authors
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU Affero General Public License as published
//! by the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//! GNU Affero General Public License for more details.
//!
//! You should have received a copy of the GNU Affero General Public License
//! along with this program. If not, see <https://www.gnu.org/licenses/>.

use Pynagent_rs::rules::security::all_security_rules;

// ============================================================================
// Rule Metadata Tests
// ============================================================================

#[test]
fn test_all_rules_have_valid_ids() {
    let rules = all_security_rules();
    assert!(!rules.is_empty(), "Should have at least some rules");

    for rule in &rules {
        let id = rule.id();
        assert!(!id.is_empty(), "Rule should have a non-empty ID");
        assert!(id.len() <= 20, "Rule ID '{}' seems too long", id);
    }
}

#[test]
fn test_all_rules_have_valid_names() {
    let rules = all_security_rules();

    for rule in &rules {
        let name = rule.name();
        assert!(!name.is_empty(), "Rule {} should have a non-empty name", rule.id());
    }
}

#[test]
fn test_rule_ids_are_unique() {
    let rules = all_security_rules();
    let mut ids: Vec<&str> = rules.iter().map(|r| r.id()).collect();
    ids.sort();
    ids.dedup();

    assert_eq!(
        ids.len(),
        rules.len(),
        "All rule IDs should be unique"
    );
}

#[test]
fn test_minimum_rule_count() {
    let rules = all_security_rules();
    assert!(
        rules.len() >= 50,
        "Should have at least 50 rules, found {}",
        rules.len()
    );
}

#[test]
fn test_php_rules_exist() {
    let rules = all_security_rules();

    // PHP rules should be in the range SEC-073 to SEC-090
    let php_rules: Vec<_> = rules.iter()
        .filter(|r| {
            let id = r.id();
            id.starts_with("SEC-07") || id.starts_with("SEC-08") || id.starts_with("SEC-09")
        })
        .collect();

    assert!(
        php_rules.len() >= 10,
        "Should have at least 10 PHP rules, found {}",
        php_rules.len()
    );
}

#[test]
fn test_all_rules_have_severity() {
    let rules = all_security_rules();

    for rule in &rules {
        let severity = rule.severity();
        assert!(
            !format!("{:?}", severity).is_empty(),
            "Rule {} should have a valid severity",
            rule.id()
        );
    }
}

// ============================================================================
// Supply Chain: Lock File Parsing
// ============================================================================

#[test]
fn test_parse_npm_package_lock_v3() {
    let lock_content = r#"{
  "name": "my-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-5n0g3xGLp4nKKx3aCj3+2+LBJ5bMBz8H5GnNj3LmfWjbU7x7t2V5oO5sXbD5J8jN6X9dW9S5y5xLrY3N3d3xL3xw=="
    }
  }
}"#;

    let packages = Pynagent_rs::scanner::supplychain::lock_parser::parse_package_lock(lock_content);
    assert!(packages.is_ok(), "Should parse valid package-lock.json v3");
    let packages = packages.unwrap();
    assert!(!packages.is_empty(), "Should extract at least one package");
    assert_eq!(packages[0].name, "express");
    assert_eq!(packages[0].version, "4.18.2");
}

#[test]
fn test_parse_npm_package_lock_v2() {
    let lock_content = r#"{
  "name": "my-project",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "dependencies": {
    "lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
    }
  }
}"#;

    let packages = Pynagent_rs::scanner::supplychain::lock_parser::parse_package_lock(lock_content);
    assert!(packages.is_ok(), "Should parse valid package-lock.json v2");
    let packages = packages.unwrap();
    assert!(!packages.is_empty(), "Should extract at least one package");
    assert_eq!(packages[0].name, "lodash");
}

#[test]
fn test_parse_cargo_lock() {
    let cargo_lock = r#"[[package]]
name = "regex"
version = "1.10.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "a233a6f00e4d0e6f7a7d93e1d8f6f7e8c3d2b5f6e8c3d2b5f6e8c3d2b5f6e8c"

[[package]]
name = "ahash"
version = "0.8.12"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2a15a8a7c7d9d8b5c7d9d9e9f9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d"
"#;

    let packages = Pynagent_rs::scanner::supplychain::lock_parser::parse_cargo_lock(cargo_lock);
    assert!(!packages.is_empty(), "Should parse Cargo.lock");
    assert_eq!(packages[0].name, "regex");
    assert_eq!(packages[0].version, "1.10.0");
}

#[test]
fn test_go_sum_integrity_check() {
    let go_sum = r#"github.com/foo/bar v1.0.0 h1:abcdef1234567890abcdefghijklmnopqrstuvwxyz1234567890AB
github.com/foo/bar v1.0.0/go.mod h1:abcdef1234567890abcdefghijklmnopqrstuvwxyz1234567890AB
github.com/baz/qux v2.1.0 h1:1234567890abcdef1234567890abcdef1234567890abcdefg
github.com/baz/qux v2.1.0/go.mod h1:abcdef1234567890abcdefghijklmnopqrstuvwxyz1234567890AB
"#;

    let results = Pynagent_rs::scanner::supplychain::lock_parser::check_go_sum(go_sum);
    assert!(!results.is_empty(), "Should check go.sum entries");
    // First entry has hash - should be OK
    // Second entry has hash - should be OK
    // Third entry has hash - should be OK
    // Fourth entry has hash - should be OK
}

#[test]
fn test_go_sum_missing_hash() {
    let go_sum = r#"github.com/foo/bar v1.0.0 h1:abcdef1234567890abcdefghijklmnopqrstuvwxyz1234567890AB
github.com/foo/bar v1.0.0/go.mod h1:abcdef1234567890abcdefghijklmnopqrstuvwxyz1234567890AB
github.com/missing/hash v1.0.0 h1:
github.com/missing/hash v1.0.0/go.mod h1:abcdef1234567890abcdefghijklmnopqrstuvwxyz1234567890AB
"#;

    let results = Pynagent_rs::scanner::supplychain::lock_parser::check_go_sum(go_sum);
    assert!(!results.is_empty(), "Should check go.sum entries");
    let missing = results.iter().find(|r| r.package.contains("missing"));
    assert!(missing.is_some(), "Should find missing hash entry");
}

#[test]
fn test_requirements_hash_mode() {
    let req_txt = r#"requests==2.31.0 \
    --hash=sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
flask==3.0.0 \
    --hash=sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
"#;

    let results = Pynagent_rs::scanner::supplychain::lock_parser::check_requirements_hash_mode(req_txt);
    // Packages with hashes are fine
    let missing = results.iter().find(|r| r.status == Pynagent_rs::scanner::supplychain::lock_parser::IntegrityStatus::MissingHash);
    assert!(missing.is_none(), "All packages have hashes");
}

#[test]
fn test_requirements_missing_hash() {
    let req_txt = r#"requests==2.31.0
flask==3.0.0
"#;

    let results = Pynagent_rs::scanner::supplychain::lock_parser::check_requirements_hash_mode(req_txt);
    assert!(!results.is_empty(), "Should check requirements.txt entries");
    let missing = results.iter().find(|r| r.status == Pynagent_rs::scanner::supplychain::lock_parser::IntegrityStatus::MissingHash);
    assert!(missing.is_some(), "Should find packages without hashes");
}

// ============================================================================
// Supply Chain: License Detection
// ============================================================================

#[test]
fn test_detect_license_mit() {
    // SPDX header format is what detect_from_license_file expects
    let content = "SPDX-License-Identifier: MIT";
    let licenses = Pynagent_rs::scanner::supplychain::license::detect_from_license_file(content);
    assert!(!licenses.is_empty(), "Should detect MIT from SPDX header");
    assert_eq!(licenses[0].spdx_id, "MIT");
}

#[test]
fn test_detect_license_apache() {
    let content = "SPDX-License-Identifier: Apache-2.0";
    let licenses = Pynagent_rs::scanner::supplychain::license::detect_from_license_file(content);
    assert!(!licenses.is_empty(), "Should detect Apache-2.0 from SPDX header");
}

#[test]
fn test_detect_license_gpl() {
    let content = "SPDX-License-Identifier: GPL-3.0-only";
    let licenses = Pynagent_rs::scanner::supplychain::license::detect_from_license_file(content);
    assert!(!licenses.is_empty(), "Should detect GPL-3.0-only from SPDX header");
}

#[test]
fn test_detect_spdx_header() {
    let content = r#"SPDX-License-Identifier: BSD-3-Clause
SPDX-License-Identifier: Apache-2.0
"#;
    let licenses = Pynagent_rs::scanner::supplychain::license::detect_from_license_file(content);
    assert!(licenses.len() >= 2, "Should detect multiple SPDX licenses");
}

// ============================================================================
// Supply Chain: SBOM Generation
// ============================================================================

#[test]
fn test_generate_spdx_sbom_structure() {
    let lock_content = r#"{
  "name": "test-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
    }
  }
}"#;

    let packages = Pynagent_rs::scanner::supplychain::lock_parser::parse_package_lock(lock_content).unwrap();
    let sbom = Pynagent_rs::scanner::supplychain::license::generate_spdx_from_packages(&packages, "test-project");

    assert_eq!(sbom.spdx_version, "SPDX-2.3");
    assert_eq!(sbom.name, "test-project");
    assert!(!sbom.packages.is_empty(), "SBOM should have packages");
    assert_eq!(sbom.packages[0].name, "lodash");
}

#[test]
fn test_generate_cyclonedx_sbom_structure() {
    let lock_content = r#"{
  "name": "test-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-5n0g3xGLp4nKKx3aCj3+2+LBJ5bMBz8H5GnNj3LmfWjbU7x7t2V5oO5sXbD5J8jN6X9dW9S5y5xLrY3N3d3xL3xw=="
    }
  }
}"#;

    let packages = Pynagent_rs::scanner::supplychain::lock_parser::parse_package_lock(lock_content).unwrap();
    let sbom = Pynagent_rs::scanner::supplychain::license::generate_cyclonedx_from_packages(&packages, "test-project");

    assert_eq!(sbom.bom_format, "CycloneDX");
    assert_eq!(sbom.spec_version, "1.5");
    assert!(!sbom.components.is_empty(), "SBOM should have components");
    assert!(!sbom.components[0].name.is_empty(), "Component should have a name");
}
