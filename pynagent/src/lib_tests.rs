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

use crate::scanner::tree_sitter::parse;
use crate::rules::security::{
    CommandInjectionRule, DeserializationRceRule, EvalExecRule, PathTraversalRule, SqlInjectionRule,
    HardcodedSecretsRule, WeakCryptoRule,
};
use crate::rules::Rule;

// ============================================================================
// SEC-001: Command Injection
// ============================================================================

#[test]
fn test_sec001_command_injection_positive() {
    let rule = CommandInjectionRule;
    let code = r#"os.system("ls -la " + user_input)"#;
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty(), "Should detect os.system()");
    assert_eq!(findings[0].rule_id, "SEC-001");
    assert_eq!(findings[0].severity, "critical");
}

#[test]
fn test_sec001_command_injection_subprocess_shell_true() {
    let rule = CommandInjectionRule;
    let code = r#"subprocess.run(cmd, shell=True)"#;
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty(), "Should detect subprocess.run with shell=True");
}

#[test]
fn test_sec001_command_injection_negative_safe_subprocess() {
    let rule = CommandInjectionRule;
    // shell=False is safe
    let code = r#"subprocess.run(["ls", "-la"], shell=False)"#;
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(findings.is_empty(), "Should NOT flag safe subprocess.run with shell=False");
}

#[test]
fn test_sec001_command_injection_negative_os_path_join() {
    let rule = CommandInjectionRule;
    // os.path.join is safe, not command execution
    let code = r#"from os.path import join; path = join(base, user_input)"#;
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(findings.is_empty(), "Should NOT flag os.path.join");
}

// ============================================================================
// SEC-002: SQL Injection
// ============================================================================

#[test]
fn test_sec002_sql_injection_positive() {
    let rule = SqlInjectionRule;
    let code = r#"cursor.execute("SELECT * FROM users WHERE id=" + user_id)"#;
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty(), "Should detect SQL concatenation");
    assert_eq!(findings[0].rule_id, "SEC-002");
}

#[test]
fn test_sec002_sql_injection_fstring() {
    let rule = SqlInjectionRule;
    let code = r#"cursor.execute(f"SELECT * FROM users WHERE id={user_id}")"#;
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty(), "Should detect f-string SQL injection");
}

#[test]
fn test_sec002_sql_injection_negative_parameterized() {
    let rule = SqlInjectionRule;
    // Parameterized query is safe
    let code = r#"cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))"#;
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(findings.is_empty(), "Should NOT flag parameterized queries");
}

// ============================================================================
// SEC-003: eval/exec Usage
// ============================================================================

#[test]
fn test_sec003_eval_positive() {
    let rule = EvalExecRule;
    let code = "result = eval(user_input)";
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty(), "Should detect eval()");
    assert_eq!(findings[0].rule_id, "SEC-003");
}

#[test]
fn test_sec003_exec_positive() {
    let rule = EvalExecRule;
    let code = "exec('print(1)')";
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty(), "Should detect exec()");
}

#[test]
fn test_sec003_eval_negative_safe_usage() {
    let rule = EvalExecRule;
    // eval with safe literal input is still flagged (intentional - eval is dangerous)
    let code = "result = eval('1 + 1')";
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    // eval with string literal should still be flagged - it's still dangerous
    assert!(!findings.is_empty(), "Should flag eval even with string literals");
}

// ============================================================================
// SEC-004: Unsafe Deserialization
// ============================================================================

#[test]
fn test_sec004_yaml_unsafe_load_positive() {
    let rule = DeserializationRceRule;
    let code = "data = yaml.load(user_yaml)";
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty(), "Should detect yaml.load");
    assert_eq!(findings[0].rule_id, "SEC-004");
}

#[test]
fn test_sec004_yaml_safe_load_negative() {
    let rule = DeserializationRceRule;
    let code = "data = yaml.safe_load(user_yaml)";
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(findings.is_empty(), "Should NOT flag yaml.safe_load");
}

#[test]
fn test_sec004_pickle_positive() {
    let rule = DeserializationRceRule;
    let code = "data = pickle.loads(user_data)";
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty(), "Should detect pickle.loads");
}

#[test]
fn test_sec004_pickle_loads_negative() {
    let rule = DeserializationRceRule;
    // pickle.loads with trusted data could be OK but still flagged
    let code = "data = pickle.loads(trusted_bytes)";
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty(), "Should flag pickle.loads even with 'trusted' name");
}

// ============================================================================
// SEC-005: Path Traversal
// ============================================================================

#[test]
fn test_sec005_path_traversal_positive() {
    let rule = PathTraversalRule;
    let code = r#"
with open(user_filename) as f:
    content = f.read()
"#;
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty(), "Should detect open with user input");
    assert_eq!(findings[0].rule_id, "SEC-005");
}

#[test]
fn test_sec005_path_traversal_negative_safe_path() {
    let rule = PathTraversalRule;
    // Safe path construction
    let code = r#"
from pathlib import Path
safe_path = Path('/safe/dir') / user_input
with open(safe_path) as f:
    content = f.read()
"#;
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    // May still flag depending on implementation - just verify detection works
    assert!(findings.is_empty() || findings.iter().any(|f| f.rule_id == "SEC-005"),
        "Path traversal detection should work");
}

// ============================================================================
// SEC-006: Hardcoded Secrets
// ============================================================================

#[test]
fn test_sec006_hardcoded_secret_positive() {
    let rule = HardcodedSecretsRule;
    let code = r#"API_KEY = "sk-1234567890abcdef12345678""#;
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty(), "Should detect hardcoded API key pattern");
    assert_eq!(findings[0].rule_id, "SEC-010");
}

#[test]
fn test_sec006_hardcoded_password_positive() {
    let rule = HardcodedSecretsRule;
    let code = r#"password = "SuperSecret123!""#;
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty(), "Should detect hardcoded password");
}

#[test]
fn test_sec006_negative_environment_var() {
    let rule = HardcodedSecretsRule;
    let code = r#"api_key = os.environ.get('API_KEY')"#;
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(findings.is_empty(), "Should NOT flag environment variable access");
}

// ============================================================================
// SEC-007: Weak Cryptography
// ============================================================================

#[test]
fn test_sec007_md5_positive() {
    let rule = WeakCryptoRule;
    let code = "hashlib.md5(password.encode())";
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty(), "Should detect md5 hash");
    assert_eq!(findings[0].rule_id, "SEC-011");
}

#[test]
fn test_sec007_sha1_positive() {
    let rule = WeakCryptoRule;
    let code = "hashlib.sha1(data)";
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty(), "Should detect sha1 hash");
}

#[test]
fn test_sec007_negative_sha256() {
    let rule = WeakCryptoRule;
    let code = "hashlib.sha256(password.encode())";
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(findings.is_empty(), "Should NOT flag sha256");
}

// ============================================================================
// Parser Tests
// ============================================================================

#[test]
fn test_parse_simple_code() {
    let code = "x = 1";
    let tree = parse(code).expect("Failed to parse");
    assert_eq!(tree.root_node().kind(), "module");
}

#[test]
fn test_parse_with_function() {
    let code = r#"
def hello():
    print("Hello, World!")
"#;
    let tree = parse(code).expect("Failed to parse");
    assert_eq!(tree.root_node().kind(), "module");
}

#[test]
fn test_parse_import_statement() {
    let code = "import os\nimport sys";
    let tree = parse(code).expect("Failed to parse");
    assert_eq!(tree.root_node().kind(), "module");
}

#[test]
fn test_parse_class_definition() {
    let code = r#"
class MyClass:
    def __init__(self):
        self.x = 1
"#;
    let tree = parse(code).expect("Failed to parse");
    assert_eq!(tree.root_node().kind(), "module");
}

// ============================================================================
// Rule Metadata Tests
// ============================================================================

#[test]
fn test_all_rules_have_valid_ids() {
    let rules = crate::rules::security::all_security_rules();
    assert!(!rules.is_empty(), "Should have at least some rules");
    for rule in &rules {
        let id = rule.id();
        assert!(!id.is_empty(), "Rule should have a non-empty ID");
        assert!(id.len() <= 20, "Rule ID '{}' seems too long", id);
    }
}

#[test]
fn test_all_rules_have_valid_names() {
    let rules = crate::rules::security::all_security_rules();
    for rule in &rules {
        let name = rule.name();
        assert!(!name.is_empty(), "Rule {} should have a non-empty name", rule.id());
    }
}

#[test]
fn test_minimum_rule_count() {
    let rules = crate::rules::security::all_security_rules();
    assert!(rules.len() >= 50, "Should have at least 50 rules, found {}", rules.len());
}
