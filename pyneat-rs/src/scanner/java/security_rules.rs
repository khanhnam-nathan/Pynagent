//! PyNeat Rust Security Scanner
//!
//! Copyright (C) 2026 PyNEAT Authors
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

use std::collections::HashSet;

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{has_import, LangRule, LangFinding};
use regex::Regex;

/// Helper: get line byte offsets (0-indexed lines, 0-indexed bytes).
fn get_line_offsets(code: &str, line: usize) -> (usize, usize) {
    let mut current_line = 1;
    let mut line_start = 0;
    for (i, c) in code.char_indices() {
        if current_line == line {
            line_start = i;
            break;
        }
        if c == '\n' {
            current_line += 1;
        }
    }
    let mut line_end = line_start;
    for (i, c) in code[line_start..].char_indices() {
        if c == '\n' {
            line_end = line_start + i + 1;
            break;
        }
    }
    if line_end == line_start {
        line_end = code.len();
    }
    (line_start, line_end)
}

/// Helper: get line number from byte offset (1-indexed).
fn get_line_from_byte(code: &str, byte: usize) -> usize {
    code[..byte].matches('\n').count() + 1
}

/// Helper: get the text content of a specific line (1-indexed).
fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|l| l.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-001: Insecure Deserialization (ObjectInputStream)
// CWE-502 — CVSS 9.8 — CRITICAL
// Common AI mistake: generates ObjectInputStream.readObject() on untrusted data
// Fix: Use JSON (Jackson/Gson) or ObjectInputFilter with whitelist
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaDeserializationRCE;

impl LangRule for JavaDeserializationRCE {
    fn id(&self) -> &str { "JAVA-SEC-001" }
    fn name(&self) -> &str { "Insecure Deserialization (ObjectInputStream)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous_imports = [
            "java.io.ObjectInputStream",
            "java.io.ObjectInput",
            "org.apache.commons.collections",
            "org.apache.commons.beanutils",
            "org.apache.commons.configuration2",
        ];
        let dangerous_calls: HashSet<&str> = [
            "readObject",
            "readUnshared",
            "ObjectInputStream",
            "XMLDecoder",
            "readXML",
        ].into_iter().collect();

        for imp in &tree.imports {
            for dangerous in &dangerous_imports {
                if imp.module.contains(dangerous) {
                    let (start, end) = get_line_offsets(code, imp.start_line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: imp.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: imp.module.clone(),
                        problem: format!(
                            "Import of '{}' indicates potential deserialization vulnerability. \
                            CWE-502: Deserialization of Untrusted Data — can lead to RCE via gadget chains.",
                            imp.module
                        ),
                        fix_hint: "Replace Java serialization with JSON (Jackson/Gson) or use \
                            ObjectInputFilter with explicit class whitelist. Never deserialize \
                            untrusted input with ObjectInputStream.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        for call in &tree.calls {
            if dangerous_calls.contains(call.callee.as_str())
                || call.callee.ends_with(".readObject")
                || call.callee.ends_with(".readUnshared")
            {
                let (start, end) = get_line_offsets(code, call.start_line);
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: call.callee.clone(),
                    problem: format!(
                        "Potentially dangerous deserialization call: '{}'. \
                        CWE-502: If input is untrusted, this can enable Remote Code Execution \
                        via gadget chains (Commons Collections, Spring AMQP, etc.).",
                        call.callee
                    ),
                    fix_hint: "Use JSON deserialization instead (Jackson ObjectMapper.readValue, \
                        Gson.fromJson). If ObjectInputStream is required, wrap with \
                        ObjectInputFilter and whitelist allowed classes.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-002: SQL Injection via String Concatenation / PreparedStatement misuse
// CWE-89 — CVSS 9.9 — CRITICAL
// AI commonly generates: "SELECT * FROM users WHERE id = " + userId
// Fix: Use PreparedStatement with ? parameters
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaSqlInjection;

impl LangRule for JavaSqlInjection {
    fn id(&self) -> &str { "JAVA-SEC-002" }
    fn name(&self) -> &str { "SQL Injection (String Concatenation)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let jdbc_imported = has_import(tree, &[
            "java.sql.", "javax.sql.", "com.mysql.", "org.postgresql.",
            "oracle.jdbc.", "com.microsoft.sqlserver.", "org.hibernate.",
        ]);

        if !jdbc_imported {
            return findings;
        }

        let jdbc_call_targets: HashSet<&str> = [
            "createStatement", "prepareStatement", "executeQuery",
            "executeUpdate", "execute", "Statement", "PreparedStatement",
        ].into_iter().collect();

        for call in &tree.calls {
            if !jdbc_call_targets.iter().any(|t| call.callee.contains(t)) {
                continue;
            }

            if let Some(first_arg) = call.arguments.first() {
                if first_arg.contains('+')
                    || first_arg.contains("\"")
                        && (first_arg.contains("SELECT ")
                            || first_arg.contains("INSERT ")
                            || first_arg.contains("UPDATE ")
                            || first_arg.contains("DELETE ")
                            || first_arg.contains("DROP ")
                            || first_arg.contains("ALTER "))
                {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = code.lines().nth(call.start_line.saturating_sub(1));
                    let snippet = line_text.unwrap_or("").trim().to_string();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: snippet.clone(),
                        problem: format!(
                            "SQL query built via string concatenation or interpolation: '{}'. \
                            CWE-89: SQL Injection — attackers can manipulate queries to access, \
                            modify, or delete data.",
                            snippet.trim()
                        ),
                        fix_hint: "Use PreparedStatement with '?' placeholders and setXxx() \
                            methods. Example: PreparedStatement ps = conn.prepareStatement( \
                            \"SELECT * FROM users WHERE id = ?\"); ps.setInt(1, userId);".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-003: XML External Entity (XXE) Injection
// CWE-611 — CVSS 8.1 — HIGH
// AI generates: DocumentBuilderFactory.newInstance() without security config
// Fix: Disable DTD, set secure XMLConstants, use SecureReader
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaXXE;

impl LangRule for JavaXXE {
    fn id(&self) -> &str { "JAVA-SEC-003" }
    fn name(&self) -> &str { "XML External Entity (XXE) Injection" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let xml_factories = [
            "DocumentBuilderFactory.newInstance",
            "SAXParserFactory.newInstance",
            "XMLInputFactory.newInstance",
            "TransformerFactory.newInstance",
            "SchemaFactory.newInstance",
            "XMLReader.newInstance",
        ];

        for call in &tree.calls {
            for factory in &xml_factories {
                if call.callee.contains(factory) {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = code.lines().nth(call.start_line.saturating_sub(1))
                        .unwrap_or("").trim().to_string();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.clone(),
                        problem: format!(
                            "XML Parser factory instantiation '{}' without explicit security \
                            configuration. CWE-611: XXE — attackers can read local files, \
                            perform SSRF, or cause DoS via crafted XML.",
                            line_text.trim()
                        ),
                        fix_hint: "Configure the factory with security hardening: \
                            factory.setFeature(XMLConstants.ACCESS_EXTERNAL_DTD, false); \
                            factory.setFeature(XMLConstants.ACCESS_EXTERNAL_SCHEMA, false); \
                            For DocumentBuilderFactory also call \
                            factory.setNamespaceAware(true) and \
                            factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);"
                            .to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        let xxe_imports = [
            "javax.xml.parsers.", "org.xml.sax.", "javax.xml.transform.",
            "org.jdom2.", "dom4j.", "org.dom4j.", "org.apache.xalan.",
        ];

        for imp in &tree.imports {
            for prefix in &xxe_imports {
                if imp.module.starts_with(prefix) {
                    let safe_factory_calls: HashSet<&str> = [
                        "setFeature", "setAttribute", "newInstance", "newSAXParser",
                    ].into_iter().collect();

                    let has_safe_config = tree.calls.iter().any(|c| {
                        safe_factory_calls.contains(c.callee.as_str())
                            && (c.callee.contains("setFeature")
                                || c.callee.contains("ACCESS_EXTERNAL"))
                    });

                    if !has_safe_config {
                        let (start, end) = get_line_offsets(code, imp.start_line);
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: imp.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: imp.module.clone(),
                            problem: "XML parsing library imported without detected security \
                                configuration. CWE-611: XXE vulnerabilities common in AI-generated \
                                Java code. XML parsers like DocumentBuilderFactory, SAXParser, \
                                and XMLInputFactory are vulnerable by default.".to_string(),
                            fix_hint: "Configure all XML factories with: \
                                setFeature(XMLConstants.ACCESS_EXTERNAL_DTD, false); \
                                setFeature(XMLConstants.ACCESS_EXTERNAL_SCHEMA, false); \
                                Consider switching to less vulnerable alternatives like \
                                javax.json.stream or Jackson dataformat-xml with secure defaults."
                                .to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-004: JNDI Injection (RMI, LDAP, CORBA lookup)
// CWE-470 — CVSS 9.8 — CRITICAL
// AI generates: ctx.lookup(name) with unvalidated user input
// Fix: Validate and sanitize JNDI names, use allowlist
// CVE-2021-44228 (Log4Shell) affected millions of Java apps
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaJndiInjection;

impl LangRule for JavaJndiInjection {
    fn id(&self) -> &str { "JAVA-SEC-004" }
    fn name(&self) -> &str { "JNDI Injection (RMI/LDAP/CORBA Lookup)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let jndi_targets: HashSet<&str> = [
            "lookup", "InitialContext.lookup", "new InitialContext",
            "doLookup", "registry.lookup",
        ].into_iter().collect();

        for call in &tree.calls {
            if jndi_targets.iter().any(|t| call.callee.contains(t)) {
                let has_param = !call.arguments.is_empty();
                let (start, end) = get_line_offsets(code, call.start_line);
                let line_text = code.lines().nth(call.start_line.saturating_sub(1))
                    .unwrap_or("").trim().to_string();

                if has_param {
                    let arg = &call.arguments[0];
                    let _is_literal = arg.starts_with('\"');
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.clone(),
                        problem: format!(
                            "JNDI lookup call '{}' with dynamic argument: '{}'. \
                            CWE-470: Unsafe use of Reflection — if argument is user-controlled, \
                            attackers can trigger RCE via malicious RMI/LDAP/CORBA references. \
                            This is the class of vulnerability behind CVE-2021-44228 (Log4Shell).",
                            call.callee, arg
                        ),
                        fix_hint: "Never pass unsanitized user input to JNDI lookup. \
                            Validate against an allowlist of permitted names. \
                            Disable remote class loading: System.setProperty( \
                            \"com.sun.jndi.rmi.object.trustURLCodebase\", \"false\"); \
                            System.setProperty(\"com.sun.jndi.ldap.object.trustURLCodebase\", \"false\");"
                            .to_string(),
                        auto_fix_available: false,
                    });
                } else {
                    let has_import = tree.imports.iter().any(|i| {
                        i.module.contains("javax.naming")
                            || i.module.contains("org.springframework.jndi")
                            || i.module.contains("org.springframework.rmi")
                    });
                    if has_import {
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.clone(),
                            problem: format!(
                                "JNDI/RMI lookup call '{}' detected in context with JNDI \
                                imports. CWE-470: JNDI injection can lead to remote code \
                                execution when attacker controls the lookup name.",
                                call.callee
                            ),
                            fix_hint: "Ensure lookup names come from a trusted allowlist only. \
                                Disable remote class loading via JVM flags: \
                                -Dcom.sun.jndi.rmi.object.trustURLCodebase=false \
                                -Dcom.sun.jndi.ldap.object.trustURLCodebase=false"
                                .to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        let jndi_imports = ["javax.naming.", "org.springframework.jndi", "org.springframework.rmi"];
        let has_jndi = has_import(tree, &jndi_imports);
        if has_jndi {
            let log4j_imported = has_import(tree, &["org.apache.log4j", "org.slf4j"]);
            if log4j_imported {
                let jndi_patterns: HashSet<&str> = [
                    "lookup", "doLookup", "new InitialContext", "InitialContext",
                ].into_iter().collect();
                let has_jndi_calls = tree.calls.iter().any(|c| {
                    jndi_patterns.iter().any(|p| c.callee.contains(p))
                });
                if !has_jndi_calls {
                    let (start, _) = get_line_offsets(code, 1);
                    let end = code.len().min(100);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: 1,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: "JNDI + Logging imports".to_string(),
                        problem: "Project uses both JNDI (javax.naming) and a logging framework \
                            (log4j/slf4j). CWE-470: JNDI injection risk present. This \
                            combination was exploited in Log4Shell (CVE-2021-44228).".to_string(),
                        fix_hint: "Ensure Log4j version is 2.17+ or 2.3.1+ (for Java 6). \
                            Set system property: log4j2.formatMsgNoLookups=true. \
                            Block JNDI at JVM level: \
                            -Dcom.sun.jndi.rmi.object.trustURLCodebase=false \
                            -Dcom.sun.jndi.ldap.object.trustURLCodebase=false"
                            .to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-005: Server-Side Request Forgery (SSRF)
// CWE-918 — CVSS 8.6 — MEDIUM
// AI generates: new URL(url).openConnection() or HttpClient.newHttpClient()
// without validating user-supplied URLs
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaSSRF;

impl LangRule for JavaSSRF {
    fn id(&self) -> &str { "JAVA-SEC-005" }
    fn name(&self) -> &str { "Server-Side Request Forgery (SSRF)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let http_imports = [
            "java.net.URL", "java.net.HttpURLConnection",
            "java.net.InetAddress", "org.springframework.web.client.",
            "org.apache.httpclient.", "org.apache.hc.client4.",
            "com.squareup.okhttp.", "okhttp3.", "java.nio.channels.SocketChannel",
        ];

        let ssrf_triggers: HashSet<&str> = [
            "openConnection", "openStream", "getInputStream",
            "send", "execute", "newHttpClient", "HttpClient.newHttpClient",
            "newBuilder", "SocketChannel.open",
            "InetAddress.getByName", "getAllByName",
        ].into_iter().collect();

        let has_http_import = has_import(tree, &http_imports);

        if has_http_import {
            for call in &tree.calls {
                if ssrf_triggers.iter().any(|t| call.callee.contains(t))
                    || call.callee.ends_with("URL")
                {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = code.lines().nth(call.start_line.saturating_sub(1))
                        .unwrap_or("").trim().to_string();

                    let arg_info = if !call.arguments.is_empty() {
                        format!(" with argument: {}", call.arguments[0])
                    } else {
                        String::new()
                    };

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.clone(),
                        problem: format!(
                            "Network request call '{}'{} detected. CWE-918: SSRF — if the URL/host \
                            is derived from user input, attackers can make the server request \
                            internal resources (metadata services, databases, internal APIs), \
                            port scan internal networks, or read local files via file:// URLs.",
                            call.callee, arg_info
                        ),
                        fix_hint: "Validate all URLs against an allowlist of permitted domains and \
                            schemes. Block file://, gopher://, dict:// schemes. \
                            Use URL normalizer to detect and reject malicious redirects. \
                            Example: WhitelistValidator.validate(url) before making the request."
                            .to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-006: SpEL Injection (Spring Expression Language)
// CWE-94 — CVSS 9.8 — CRITICAL
// AI generates: SpEL expressions parsed from user input without sandbox
// CVE-2026-22738: Spring AI SimpleVectorStore SpEL injection
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaSpELInjection;

impl LangRule for JavaSpELInjection {
    fn id(&self) -> &str { "JAVA-SEC-006" }
    fn name(&self) -> &str { "SpEL Injection (Spring Expression Language)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let spel_imports = [
            "org.springframework.expression.",
            "org.springframework.data.commons.",
            "org.springframework.data.mongodb.",
        ];

        let spel_methods: HashSet<&str> = [
            "parseExpression", "getExpression", "ExpressionParser.parseExpression",
            "SpelExpressionParser.", "StandardEvaluationContext.",
            "SimpleEvaluationContext.", "EvaluationContext",
        ].into_iter().collect();

        let has_spel = has_import(tree, &spel_imports);

        if has_spel {
            for call in &tree.calls {
                if spel_methods.iter().any(|m| call.callee.contains(m)) {
                    let is_user_controlled = !call.arguments.is_empty()
                        && call.arguments.iter().any(|a| {
                            a.contains("request") || a.contains("param")
                                || a.contains("body") || a.contains("header")
                                || a.contains("input") || a.contains("user")
                        });

                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = code.lines().nth(call.start_line.saturating_sub(1))
                        .unwrap_or("").trim().to_string();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.clone(),
                        problem: format!(
                            "SpEL expression parsing detected: '{}'. CWE-94: Code Injection — \
                            if expression source is user-controlled, attackers can achieve RCE. \
                            CVE-2026-22738: Spring AI SimpleVectorStore SpEL injection (CVSS 9.3). \
                            AI-generated code often uses user input directly in SpEL.",
                            line_text.trim()
                        ),
                        fix_hint: "Never parse SpEL expressions from untrusted input. \
                            Use SimpleEvaluationContext (restricted) instead of \
                            StandardEvaluationContext (full Java object access). \
                            If user input must be in an expression, use strict allowlist: \
                            TemplateParserContext with #{} syntax and validate variable names."
                            .to_string(),
                        auto_fix_available: false,
                    });

                    if is_user_controlled && findings.last().map(|f| f.line == call.start_line).unwrap_or(false) {
                        if let Some(last) = findings.last_mut() {
                            last.problem = format!(
                                "URGENT: SpEL parsing with LIKELY user-controlled input: '{}'. \
                                CWE-94: RCE via SpEL injection is trivially exploitable. \
                                This is how CVE-2026-22738 (Spring AI, CVSS 9.3) works.",
                                last.snippet.trim()
                            );
                        }
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-007: Hardcoded Secrets / Credentials
// CWE-798 — CVSS 7.5 — HIGH
// AI frequently generates code with hardcoded passwords, API keys, tokens
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaHardcodedSecrets;

impl LangRule for JavaHardcodedSecrets {
    fn id(&self) -> &str { "JAVA-SEC-007" }
    fn name(&self) -> &str { "Hardcoded Secrets / Credentials" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let secret_patterns = [
            (r#""(?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|bearer|jwt|private[_-]?key|aws[_-]?secret)"[=:]\s*"[^"]{4,}""#, "hardcoded credential pattern"),
            (r#"(?i)password\s*=\s*"[^"]{4,}""#, "hardcoded password"),
            (r#"(?i)(api[_-]?key|api[_-]?secret)\s*=\s*"[^"]{8,}""#, "hardcoded API key"),
            (r#"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"#, "hardcoded JWT/bearer token"),
            (r#"(?i)(aws[_-]?(access[_-]?key[_-]?id|secret[_-]?access[_-]?key))\s*[=:]\s*"[^"]{10,}""#, "hardcoded AWS credentials"),
            (r#"ConnectionString\s*[=:]\s*"[^"]*password[^"]*""#, "hardcoded connection string with password"),
        ];

        let lines: Vec<&str> = code.lines().collect();
        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1;
            for (pattern, desc) in &secret_patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if re.is_match(line) {
                        for m in re.find_iter(line) {
                            let (start_byte, _) = get_line_offsets(code, line_num);
                            let abs_start = start_byte + line.len() - line.trim_start().len();
                            let abs_end = abs_start + line.len();

                            findings.push(LangFinding {
                                rule_id: self.id().to_string(),
                                severity: self.severity().to_string(),
                                line: line_num,
                                column: m.start(),
                                start_byte: abs_start,
                                end_byte: abs_end,
                                snippet: m.as_str().to_string(),
                                problem: format!(
                                    "Hardcoded secret detected: {}. CWE-798: Found credentials, \
                                    API keys, or tokens directly in source code. These can be \
                                    extracted from repositories, bytecode, or decompiled APKs.",
                                    desc
                                ),
                                fix_hint: "Move secrets to environment variables (System.getenv()), \
                                    secure vaults (HashiCorp Vault, AWS Secrets Manager), \
                                    Spring Cloud Config, or Kubernetes secrets. \
                                    Use getProperty(\"DB_PASSWORD\") and set via environment."
                                    .to_string(),
                                auto_fix_available: false,
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-008: Weak / Broken Cryptography
// CWE-327 — CVSS 7.4 — HIGH
// AI generates: MD5/SHA1 for passwords, weak DES, ECB mode, no IV
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaWeakCrypto;

impl LangRule for JavaWeakCrypto {
    fn id(&self) -> &str { "JAVA-SEC-008" }
    fn name(&self) -> &str { "Weak / Broken Cryptography" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let weak_algo_imports = [
            ("DES", "javax.crypto.Cipher", "CWE-327: DES is broken (56-bit key). Use AES-256."),
            ("3DES", "javax.crypto.Cipher", "CWE-327: Triple-DES has small effective key size. Use AES."),
            ("RC4", "javax.crypto.Cipher", "CWE-327: RC4 is broken. Use AES."),
            ("MD5", "java.security.MessageDigest", "CWE-327: MD5 is broken for security. Use SHA-256+."),
            ("SHA1", "java.security.MessageDigest", "CWE-327: SHA-1 is deprecated for signatures. Use SHA-256+."),
            ("NoPadding", "javax.crypto.Cipher", "CWE-327: NoPadding with symmetric cipher reveals patterns. Use PKCS5Padding or GCM."),
            ("ECB", "javax.crypto.Cipher", "CWE-327: ECB mode leaks patterns — identical plaintexts produce identical ciphertexts. Use GCM or CBC with random IV."),
        ];

        for imp in &tree.imports {
            for (algo, lib, msg) in &weak_algo_imports {
                if imp.module.contains(lib) && imp.module.contains(algo) {
                    let (start, end) = get_line_offsets(code, imp.start_line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: imp.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: imp.module.clone(),
                        problem: format!(
                            "Weak or broken cryptography algorithm detected: {} import. {}",
                            algo, msg
                        ),
                        fix_hint: "Use AES-256-GCM for encryption (provides both confidentiality \
                            and authenticity). For hashing, use SHA-256 or SHA-3. \
                            For passwords, use BCrypt, Argon2, or PBKDF2 (not plain SHA). \
                            Example: Cipher.getInstance(\"AES/GCM/NoPadding\") with GCMParameterSpec."
                            .to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        let weak_method_patterns = [
            (r#"MessageDigest\.getInstance\s*\(\s*["']MD5["']\s*\)"#, "MD5 hash", "Use SHA-256 or SHA-3 instead."),
            (r#"MessageDigest\.getInstance\s*\(\s*["']SHA-?1["']\s*\)"#, "SHA-1 hash", "Use SHA-256 or SHA-3 instead."),
            (r#"Cipher\.getInstance\s*\([^)]*\bDES\b[^)]*\)"#, "DES cipher", "Use AES-256-GCM instead."),
            (r#"Cipher\.getInstance\s*\([^)]*\bRC4\b[^)]*\)"#, "RC4 cipher", "Use AES-256-GCM instead."),
            (r#"Cipher\.getInstance\s*\([^)]*\bECB\b[^)]*\)"#, "ECB mode", "Use GCM or CBC with random IV instead."),
        ];

        for call in &tree.calls {
            for (pattern, name, fix) in &weak_method_patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    let line_text = code.lines().nth(call.start_line.saturating_sub(1))
                        .unwrap_or("");
                    if re.is_match(line_text) {
                        let (start, end) = get_line_offsets(code, call.start_line);
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.trim().to_string(),
                            problem: format!(
                                "Weak cryptography detected: {} call. CWE-327: {}.",
                                name, fix
                            ),
                            fix_hint: fix.to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-009: Command Injection via Runtime.exec / ProcessBuilder
// CWE-78 — CVSS 9.8 — CRITICAL
// AI generates: Runtime.getRuntime().exec("ls " + userInput)
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaCommandInjection;

impl LangRule for JavaCommandInjection {
    fn id(&self) -> &str { "JAVA-SEC-009" }
    fn name(&self) -> &str { "Command Injection (Runtime.exec / ProcessBuilder)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let cmd_targets: HashSet<&str> = [
            "Runtime.getRuntime().exec",
            "ProcessBuilder.",
            "java.lang.Runtime",
        ].into_iter().collect();

        for call in &tree.calls {
            if cmd_targets.iter().any(|t| call.callee.contains(t)) {
                let (start, end) = get_line_offsets(code, call.start_line);
                let line_text = code.lines().nth(call.start_line.saturating_sub(1))
                    .unwrap_or("").trim().to_string();

                let is_concatenated = !call.arguments.is_empty()
                    && call.arguments.iter().any(|a| a.contains('+'));

                if is_concatenated {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.clone(),
                        problem: format!(
                            "Command execution '{}' with string concatenation of arguments. \
                            CWE-78: Command Injection — attackers can execute arbitrary OS commands \
                            on the host. This is a critical RCE vector.",
                            line_text.trim()
                        ),
                        fix_hint: "Use ProcessBuilder with an array of arguments (String[]) and \
                            avoid shell interpretation. Never concatenate user input into commands. \
                            Example: new ProcessBuilder(\"ls\", \"-la\", userInput) — note NO shell=True."
                            .to_string(),
                        auto_fix_available: false,
                    });
                } else if !call.arguments.is_empty() {
                    let arg = &call.arguments[0];
                    let is_dynamic = arg.contains("request") || arg.contains("param")
                        || arg.contains("input") || arg.contains("user");
                    if is_dynamic {
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.clone(),
                            problem: format!(
                                "Command execution '{}' with dynamic input. CWE-78: \
                                Command Injection — if '{}' is user-controlled, this is exploitable.",
                                call.callee, arg
                            ),
                            fix_hint: "Validate and sanitize all input going to command execution. \
                                Use an allowlist for permitted values. Prefer ProcessBuilder \
                                over Runtime.exec() and pass arguments as separate array elements."
                                .to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-010: Path Traversal / Arbitrary File Read
// CWE-22 — CVSS 8.6 — HIGH
// AI generates: new FileInputStream(userInput) without sanitization
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaPathTraversal;

impl LangRule for JavaPathTraversal {
    fn id(&self) -> &str { "JAVA-SEC-010" }
    fn name(&self) -> &str { "Path Traversal / Arbitrary File Read" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let file_api_imports = [
            "java.io.FileInputStream", "java.io.File", "java.io.FileReader",
            "java.nio.file.Paths.get", "java.nio.file.Path",
            "org.springframework.core.io.ResourceLoader",
            "javax.servlet.http.HttpServletRequest",
        ];

        let file_targets: HashSet<&str> = [
            "FileInputStream", "FileReader", "File.", "new File",
            "Paths.get", "Path.of", "getInputStream",
            "getParameter", "getHeader", "getQueryString",
        ].into_iter().collect();

        let has_file_import = has_import(tree, &file_api_imports);

        if has_file_import {
            for call in &tree.calls {
                if file_targets.iter().any(|t| call.callee.contains(t)) {
                    let is_user_controlled = !call.arguments.is_empty()
                        && call.arguments.iter().any(|a| {
                            a.contains("request") || a.contains("param")
                                || a.contains("header") || a.contains("userInput")
                                || a.contains("filename") || a.contains("path")
                        });

                    let has_sanitization = tree.calls.iter().any(|c| {
                        c.callee.contains("normalize")
                            || c.callee.contains("toRealPath")
                            || c.callee.contains("getCanonicalPath")
                            || c.callee.contains("startsWith")
                    });

                    if is_user_controlled && !has_sanitization {
                        let (start, end) = get_line_offsets(code, call.start_line);
                        let line_text = code.lines().nth(call.start_line.saturating_sub(1))
                            .unwrap_or("").trim().to_string();

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.clone(),
                            problem: format!(
                                "File operation '{}' with likely user-controlled path and no \
                                sanitization. CWE-22: Path Traversal — attackers can use \
                                '../' sequences to read arbitrary files like /etc/passwd, \
                                application config, or source code.",
                                line_text.trim()
                            ),
                            fix_hint: "Validate the path against an allowlist of permitted directories. \
                                Use Path.normalize().toRealPath() to resolve symlinks. \
                                Check: if (!path.normalize().startsWith(ALLOWED_DIR)) throw Exception. \
                                Prefer Path.of() over File constructor (more predictable)."
                                .to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-011: Spring Security Misconfiguration
// CWE-284 / CWE-285 — CVSS 7.5 — HIGH
// AI generates: Spring Security config with permitAll() on sensitive endpoints
// or missing authorization checks
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaSpringSecurityMisconfig;

impl LangRule for JavaSpringSecurityMisconfig {
    fn id(&self) -> &str { "JAVA-SEC-011" }
    fn name(&self) -> &str { "Spring Security Misconfiguration" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let spring_security_imports = [
            "org.springframework.security",
            "org.springframework.web.servlet.config.annotation",
        ];

        let has_spring_security = has_import(tree, &spring_security_imports);

        if !has_spring_security {
            return findings;
        }

        let dangerous_patterns = [
            (r#"\bpermitAll\(\)"#, "permitAll() — allows unauthenticated access"),
            (r#"\bhasRole\s*\(\s*["'][^"]+["']\s*\)\s*(?:&&|\|\|)"#, "complex hasRole with possible bypass"),
            (r#"\bpermitAll\s*\(\s*["'][^"']*(?:admin|user|role|manage|config|secret|key)[^"']*["']\s*\)"#, "permitAll on sensitive path"),
            (r#"\bcsrf\(\)\.disable\(\)"#, "CSRF disabled globally (may be needed for APIs, but risky for browser clients)"),
            (r#"@PreAuthorize\s*\(\s*["']isAnonymous\(\)"#, "Anonymous access allowed on annotated endpoint"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            for (pattern, desc) in &dangerous_patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if re.is_match(line) {
                        let (start_byte, _) = get_line_offsets(code, line_num);
                        let abs_start = start_byte + line.len() - line.trim_start().len();
                        let abs_end = abs_start + line.len();

                        let severity = if desc.contains("permitAll")
                            && (line.contains("admin") || line.contains("manage")
                                || line.contains("config") || line.contains("secret"))
                        {
                            "critical"
                        } else {
                            self.severity()
                        };

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: severity.to_string(),
                            line: line_num,
                            column: 0,
                            start_byte: abs_start,
                            end_byte: abs_end,
                            snippet: line.trim().to_string(),
                            problem: format!(
                                "Spring Security misconfiguration: {}. CWE-284/CWE-285: \
                                Access Control issues — '{}'. AI-generated Spring Security \
                                configs often leave sensitive endpoints publicly accessible.",
                                desc, line.trim()
                            ),
                            fix_hint: "Review all permitAll() calls carefully. Admin, config, \
                                and management endpoints should require authentication and \
                                specific roles. Only disable CSRF for stateless REST APIs \
                                using cookies for authentication. Prefer @PreAuthorize \
                                with explicit role checks over global permitAll()."
                                .to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-012: Log Injection / Information Disclosure
// CWE-117 / CWE-532 — CVSS 4.6 — LOW
// AI generates: logger.info(userInput) without sanitization
// Attackers inject fake log entries or steal via log exfiltration
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaLogInjection;

impl LangRule for JavaLogInjection {
    fn id(&self) -> &str { "JAVA-SEC-012" }
    fn name(&self) -> &str { "Log Injection / Information Disclosure in Logs" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let logger_imports = [
            "org.slf4j.Logger", "org.apache.logging.log4j.Logger",
            "org.apache.log4j.Logger", "java.util.logging.Logger",
            "ch.qos.logback", "org.jboss.logging",
        ];

        let log_methods: HashSet<&str> = [
            "Logger.info", "Logger.debug", "Logger.warn", "Logger.error",
            "Logger.trace", "log.info", "log.debug", "log.warn", "log.error",
            "log.trace", "System.out.println", "System.err.println",
        ].into_iter().collect();

        let has_logger = has_import(tree, &logger_imports);

        if has_logger {
            for call in &tree.calls {
                if log_methods.iter().any(|m| call.callee.contains(m)) {
                    let is_user_controlled = !call.arguments.is_empty()
                        && call.arguments.iter().any(|a| {
                            a.contains("request") || a.contains("param")
                                || a.contains("header") || a.contains("body")
                                || a.contains("input") || a.contains("user")
                                || a.contains("cookie") || a.contains("username")
                        });

                    if is_user_controlled {
                        let (start, end) = get_line_offsets(code, call.start_line);
                        let line_text = code.lines().nth(call.start_line.saturating_sub(1))
                            .unwrap_or("").trim().to_string();

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.clone(),
                            problem: format!(
                                "Log statement '{}' with user-controlled input. CWE-117: \
                                Log Injection — attackers can inject newline characters to \
                                forge log entries (log injection attack), or exfiltrate \
                                sensitive data via crafted input. Also CWE-532: Information \
                                Disclosure through log files.",
                                line_text.trim()
                            ),
                            fix_hint: "Sanitize all user input before logging. Remove or \
                                escape newlines, carriage returns, and special characters. \
                                Use structured logging with parameterized messages: \
                                logger.info(\"User {} logged in\", username) instead of \
                                logger.info(username). Never log passwords, tokens, or PII."
                                .to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        let sensitive_patterns = [
            (r#"(?i)log(?:ger)?\.[a-z]+\([^)]*(?:password|passwd|secret|token|key|auth)[^)]*\)"#, "sensitive data in log"),
            (r#"System\.(out|err)\.print(?:ln)?\([^)]*(?:password|secret|token|key)[^)]*\)"#, "sensitive data in stdout/stderr"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            for (pattern, desc) in &sensitive_patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if re.is_match(line) {
                        let (start_byte, _) = get_line_offsets(code, line_num);
                        let abs_start = start_byte + line.len() - line.trim_start().len();
                        let abs_end = abs_start + line.len();

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: line_num,
                            column: 0,
                            start_byte: abs_start,
                            end_byte: abs_end,
                            snippet: line.trim().to_string(),
                            problem: format!(
                                "Sensitive data logged: {}. CWE-532: Information Disclosure — \
                                passwords, secrets, tokens, or keys in logs can be read by \
                                anyone with access to log files or monitoring systems.",
                                desc
                            ),
                            fix_hint: "Never log sensitive fields. Use structured logging \
                                frameworks and exclude sensitive fields from serialization. \
                                Implement a custom appender or use tools like logback-mask \
                                to automatically mask sensitive patterns."
                                .to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-013: LDAP Injection
// CWE-90 — CVSS 6.1 — MEDIUM
// AI generates: ctx.search(name, filter) with unsanitized user input in filter
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaLdapInjection;

impl LangRule for JavaLdapInjection {
    fn id(&self) -> &str { "JAVA-SEC-013" }
    fn name(&self) -> &str { "LDAP Injection" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let ldap_imports = [
            "javax.naming.ldap.", "javax.naming.directory.",
            "org.springframework.ldap",
        ];

        let ldap_methods: HashSet<&str> = [
            "search", "searchControls", "getAttributes",
            "DirContext.search", "LdapContext",
            "InitialLdapContext",
        ].into_iter().collect();

        let has_ldap = has_import(tree, &ldap_imports);

        if has_ldap {
            for call in &tree.calls {
                if ldap_methods.iter().any(|m| call.callee.contains(m)) {
                    let has_dynamic_filter = !call.arguments.is_empty()
                        && call.arguments.iter().any(|a| {
                            a.contains("+") || a.contains("request")
                                || a.contains("param") || a.contains("input")
                        });

                    if has_dynamic_filter {
                        let (start, end) = get_line_offsets(code, call.start_line);
                        let line_text = code.lines().nth(call.start_line.saturating_sub(1))
                            .unwrap_or("").trim().to_string();

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.clone(),
                            problem: format!(
                                "LDAP search with dynamic filter: '{}'. CWE-90: LDAP Injection — \
                                attackers can manipulate LDAP queries via special characters \
                                (*, (, ), \\, NUL) to bypass authentication or extract \
                                unauthorized directory information.",
                                line_text.trim()
                            ),
                            fix_hint: "Escape special LDAP characters in user input: \
                                *, (, ), \\, NUL, /. Use DN escaping: replace \\ -> \\\\5c, \
                                * -> \\\\2a, ( -> \\\\28, ) -> \\\\29, NUL -> \\\\00. \
                                Prefer direct DN construction with validated input over \
                                search-based lookup when possible."
                                .to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-014: Unsafe Reflection / Class Loading
// CWE-470 — CVSS 9.1 — CRITICAL
// AI generates: Class.forName(userInput) or Method.invoke() without validation
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaUnsafeReflection;

impl LangRule for JavaUnsafeReflection {
    fn id(&self) -> &str { "JAVA-SEC-014" }
    fn name(&self) -> &str { "Unsafe Reflection / Class Loading" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let reflection_imports = [
            "java.lang.reflect.", "java.lang.Class",
            "java.lang.ClassLoader", "javax.script.",
        ];

        let reflection_methods: HashSet<&str> = [
            "Class.forName", "ClassLoader.loadClass",
            "Method.invoke", "Field.get", "Field.set",
            "Constructor.newInstance", "ScriptEngine.eval",
            "GroovyClassLoader", "URLClassLoader",
        ].into_iter().collect();

        let has_reflection = has_import(tree, &reflection_imports);

        if has_reflection {
            for call in &tree.calls {
                if reflection_methods.iter().any(|m| call.callee.contains(m)) {
                    let is_user_controlled = !call.arguments.is_empty()
                        && call.arguments.iter().any(|a| {
                            a.contains("request") || a.contains("param")
                                || a.contains("input") || a.contains("className")
                                || a.contains("user")
                        });

                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = code.lines().nth(call.start_line.saturating_sub(1))
                        .unwrap_or("").trim().to_string();

                    if is_user_controlled {
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.clone(),
                            problem: format!(
                                "Reflection call '{}' with user-controlled class/method name. \
                                CWE-470: Unsafe Reflection — attackers can instantiate \
                                arbitrary classes (Runtime, ProcessBuilder) leading to RCE. \
                                This is the foundation of many deserialization exploits.",
                                line_text.trim()
                            ),
                            fix_hint: "NEVER pass user input to Class.forName, Method.invoke, \
                                or similar reflection APIs. Use an explicit allowlist of \
                                permitted class names. Consider disabling classpath scanning \
                                in production. For plugin systems, use a dedicated sandbox \
                                (Java SecurityManager or newer sandboxing mechanisms)."
                                .to_string(),
                            auto_fix_available: false,
                        });
                    } else {
                        let has_validation = tree.calls.iter().any(|c| {
                            c.callee.contains("startsWith") || c.callee.contains("equals")
                                || c.callee.contains("allowlist") || c.callee.contains("whitelist")
                        });
                        if !has_validation {
                            findings.push(LangFinding {
                                rule_id: self.id().to_string(),
                                severity: "high".to_string(),
                                line: call.start_line,
                                column: 0,
                                start_byte: start,
                                end_byte: end,
                                snippet: line_text.clone(),
                                problem: format!(
                                    "Reflection API call '{}' without detected validation. \
                                    CWE-470: Even without direct user control, unvalidated \
                                    reflection can be exploited if the class name comes \
                                    from config, headers, or indirect input.",
                                    line_text.trim()
                                ),
                                fix_hint: "Add explicit allowlist validation for all \
                                    class/method names used in reflection. Example: \
                                    if (!ALLOWED_CLASSES.contains(className)) throw SecurityException."
                                    .to_string(),
                                auto_fix_available: false,
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-015: Mass Assignment / Object Deserialization from Untrusted JSON
// CWE-915 — CVSS 6.5 — MEDIUM
// AI generates: objectMapper.readValue(json, clazz) without type validation
// Attackers set unexpected fields like isAdmin, role, balance
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaMassAssignment;

impl LangRule for JavaMassAssignment {
    fn id(&self) -> &str { "JAVA-SEC-015" }
    fn name(&self) -> &str { "Mass Assignment / Unsafe JSON Deserialization" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let json_imports = [
            "com.fasterxml.jackson.databind.ObjectMapper",
            "com.google.gson.Gson", "com.google.gson.JsonParser",
            "org.codehaus.jackson.map.ObjectMapper",
            "com.fasterxml.jackson.databind.node.",
        ];

        let json_methods: HashSet<&str> = [
            "readValue", "readTree", "fromJson", "parse",
            "ObjectMapper", "Gson", "treeToValue",
        ].into_iter().collect();

        let has_json_lib = has_import(tree, &json_imports);

        if has_json_lib {
            for call in &tree.calls {
                if json_methods.iter().any(|m| call.callee.contains(m)) {
                    let is_user_controlled = !call.arguments.is_empty()
                        && call.arguments.iter().any(|a| {
                            a.contains("request") || a.contains("input")
                                || a.contains("body") || a.contains("param")
                                || a.contains("json") || a.contains("payload")
                        });

                    if is_user_controlled {
                        let (start, end) = get_line_offsets(code, call.start_line);
                        let line_text = code.lines().nth(call.start_line.saturating_sub(1))
                            .unwrap_or("").trim().to_string();

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.clone(),
                            problem: format!(
                                "JSON deserialization from user input: '{}'. CWE-915: \
                                Mass Assignment — attackers can set unexpected fields \
                                (isAdmin=true, role=\"admin\", balance=999999) by including \
                                them in JSON. AI-generated DTOs often lack @JsonIgnore, \
                                @JsonView, or validation annotations.",
                                line_text.trim()
                            ),
                            fix_hint: "Use @JsonIgnore, @JsonIgnoreProperties, or @JsonView \
                                to control which fields can be deserialized. \
                                Implement input validation with Bean Validation (JSR-380): \
                                @Valid + @NotNull, @Min, @Max on DTO fields. \
                                Consider using a strict deserialization approach: \
                                objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)."
                                .to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-016: Template Injection (FreeMarker, Velocity, Thymeleaf)
// CWE-1336 — CVSS 9.8 — CRITICAL
// AI generates: engine.render(template, ctx) where ctx contains user input
// Similar to SpEL but for server-side template engines
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaTemplateInjection;

impl LangRule for JavaTemplateInjection {
    fn id(&self) -> &str { "JAVA-SEC-016" }
    fn name(&self) -> &str { "Server-Side Template Injection (SSTI)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let template_imports = [
            "freemarker.template.", "org.apache.velocity.",
            "org.apache Velocity", "org.thymeleaf.",
            "org.apache.struts2.views.", "org.apache.tiles.",
            "pebble.", "org.pebble",
        ];

        let template_methods: HashSet<&str> = [
            "Template.process", "Velocity.evaluate",
            "template.process", "Template.getRawTemplate",
            "engine.process", "ThymeleafUtil",
        ].into_iter().collect();

        let has_template = has_import(tree, &template_imports);

        if has_template {
            for call in &tree.calls {
                if template_methods.iter().any(|m| call.callee.contains(m)) {
                    let has_user_ctx = !call.arguments.is_empty()
                        && call.arguments.iter().any(|a| {
                            a.contains("request") || a.contains("params")
                                || a.contains("input") || a.contains("user")
                        });

                    if has_user_ctx {
                        let (start, end) = get_line_offsets(code, call.start_line);
                        let line_text = code.lines().nth(call.start_line.saturating_sub(1))
                            .unwrap_or("").trim().to_string();

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.clone(),
                            problem: format!(
                                "Template rendering with user-controlled context: '{}'. \
                                CWE-1336: Server-Side Template Injection — attackers can \
                                inject template directives to achieve RCE (execute OS commands, \
                                read files). AI-generated template rendering code often \
                                passes user input directly into the template context.",
                                line_text.trim()
                            ),
                            fix_hint: "Never pass unsanitized user input directly to template \
                                engines. Use template rendering only with pre-validated data. \
                                For FreeMarker, use ?esc or <#noparse> carefully. \
                                Consider sandboxing templates with RestrictedClassResolver. \
                                Example: cfg.setNewBuiltinClassResolver( \
                                new SecurityFM3RestrictedClassResolver());"
                                .to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-017: XMLDecoder XSS / Code Injection
// CWE-20 — CVSS 9.8 — CRITICAL
// AI generates: new XMLDecoder(is).readObject() on user-provided XML
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaXMLDecoder;

impl LangRule for JavaXMLDecoder {
    fn id(&self) -> &str { "JAVA-SEC-017" }
    fn name(&self) -> &str { "XMLDecoder Code Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let xmldecoder_imports = ["java.beans.XMLDecoder"];

        let xmldecoder_methods: HashSet<&str> = [
            "XMLDecoder.", "readObject", "XMLDecoder",
        ].into_iter().collect();

        let has_xmldecoder = has_import(tree, &xmldecoder_imports);

        if has_xmldecoder {
            for call in &tree.calls {
                if xmldecoder_methods.iter().any(|m| call.callee.contains(m)) {
                    let is_user_input = !call.arguments.is_empty()
                        && call.arguments.iter().any(|a| {
                            a.contains("request") || a.contains("input")
                                || a.contains("body") || a.contains("stream")
                        });

                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = code.lines().nth(call.start_line.saturating_sub(1))
                        .unwrap_or("").trim().to_string();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.clone(),
                        problem: format!(
                            "XMLDecoder usage: '{}'. CWE-20: XMLDecoder deserializes Java \
                            objects from XML — if input is user-controlled, attackers can \
                            inject arbitrary method calls (e.g., <void class=\"java.lang.Runtime\" \
                            method=\"exec\"><string>calc</string></void> for RCE). \
                            This is a well-known RCE vector in Java.",
                            line_text.trim()
                        ),
                        fix_hint: "AVOID XMLDecoder entirely for untrusted input. \
                            Replace with JSON serialization (Jackson, Gson) which does \
                            not execute code. If XMLDecoder is required for trusted input, \
                            implement strict input validation and consider wrapping \
                            with a SecurityManager (though deprecated in recent JVMs, \
                            a custom SecurityManager class is still viable)."
                            .to_string(),
                        auto_fix_available: false,
                    });

                    if is_user_input && findings.last().map(|f| f.line == call.start_line).unwrap_or(false) {
                        if let Some(last) = findings.last_mut() {
                            last.problem = format!(
                                "CRITICAL: XMLDecoder on user-controlled input: '{}'. \
                                CWE-20: This is trivially exploitable for RCE.",
                                last.snippet.trim()
                            );
                        }
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-018: Type Confusion / Unsafe Type Casting
// CWE-843 — CVSS 7.5 — HIGH
// AI generates: (MyClass) obj without instanceof check
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaTypeConfusion;

impl LangRule for JavaTypeConfusion {
    fn id(&self) -> &str { "JAVA-SEC-018" }
    fn name(&self) -> &str { "Type Confusion / Unsafe Type Casting" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let mut prev_was_instanceof = false;
        let mut last_instanceof_line = 0;

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            if trimmed.starts_with("instanceof")
                || trimmed.contains(" instanceof ")
                || trimmed.starts_with("if (")
                    && (trimmed.contains("instanceof") || trimmed.contains("getClass()"))
            {
                prev_was_instanceof = true;
                last_instanceof_line = line_num;
                continue;
            }

            if prev_was_instanceof && last_instanceof_line == line_num - 1 {
                let cast_pattern = regex::Regex::new(r#"\(\s*([A-Z][a-zA-Z0-9_]*)\s*\)\s*\w"#).ok();
                if let Some(re) = cast_pattern {
                    if re.is_match(trimmed) {
                        let (start_byte, _) = get_line_offsets(code, line_num);
                        let abs_start = start_byte + line.len() - trimmed.len();
                        let abs_end = abs_start + trimmed.len();

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: line_num,
                            column: 0,
                            start_byte: abs_start,
                            end_byte: abs_end,
                            snippet: trimmed.to_string(),
                            problem: "Type casting after instanceof check found. \
                                CWE-843: Type Confusion — AI-generated code may cast to wrong \
                                type or miss edge cases in inheritance hierarchies.".to_string(),
                            fix_hint: "Ensure instanceof checks cover the full type hierarchy. \
                                Use pattern matching with instanceof (Java 16+): \
                                if (obj instanceof MyClass c) { c.doSomething(); } \
                                instead of separate instanceof + cast blocks."
                                .to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }

            if !trimmed.contains("instanceof") && !trimmed.contains("getClass()") {
                prev_was_instanceof = false;
            }
        }

        let unsafe_cast_pattern = regex::Regex::new(r#"\(\s*([A-Z][a-zA-Z0-9_<>]*)\s*\)\s*(?:obj|object|value|param|input|result|data)"#).ok();
        if let Some(re) = unsafe_cast_pattern {
            for (line_idx, line) in code.lines().enumerate() {
                let line_num = line_idx + 1;
                if let Some(m) = re.find(line) {
                    if !line.contains("instanceof") && !line.contains("getClass()")
                        && !line.contains("getDeclaredField")
                    {
                        let (start_byte, _) = get_line_offsets(code, line_num);
                        let abs_start = start_byte + line.len() - line.trim_start().len();
                        let abs_end = abs_start + line.len();

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: "medium".to_string(),
                            line: line_num,
                            column: 0,
                            start_byte: abs_start,
                            end_byte: abs_end,
                            snippet: line.trim().to_string(),
                            problem: format!(
                                "Unchecked type cast detected: '{}'. CWE-843: Type Confusion — \
                                casting without prior instanceof/getClass() check can cause \
                                ClassCastException or, in polymorphic contexts, type confusion \
                                vulnerabilities.",
                                m.as_str()
                            ),
                            fix_hint: "Always check type with instanceof before casting. \
                                Use Java 16+ pattern matching: \
                                if (obj instanceof MyClass c) { /* use c */ }"
                                .to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-019: Insecure Cookie / Session Configuration
// CWE-614 / CWE-1004 — CVSS 6.5 — MEDIUM
// AI generates: cookie without HttpOnly, Secure, SameSite flags
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaInsecureCookie;

impl LangRule for JavaInsecureCookie {
    fn id(&self) -> &str { "JAVA-SEC-019" }
    fn name(&self) -> &str { "Insecure Cookie / Session Configuration" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let servlet_imports = [
            "javax.servlet.http.", "jakarta.servlet.http.",
        ];

        let cookie_methods: HashSet<&str> = [
            "HttpServletResponse.addCookie",
            "new Cookie", "Cookie",
            "HttpSession.setAttribute",
            "response.addHeader", "setMaxAge", "setPath",
        ].into_iter().collect();

        let has_servlet = has_import(tree, &servlet_imports);

        if has_servlet {
            let has_http_only = tree.calls.iter().any(|c| {
                c.callee.contains("setHttpOnly") || c.callee.contains("HttpOnly")
            });
            let has_secure = tree.calls.iter().any(|c| {
                c.callee.contains("setSecure") || c.callee.contains("Secure")
            });
            let has_same_site = tree.calls.iter().any(|c| {
                c.callee.contains("setAttribute") && c.callee.contains("SameSite")
            });

            for call in &tree.calls {
                if cookie_methods.iter().any(|m| call.callee.contains(m)) {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = code.lines().nth(call.start_line.saturating_sub(1))
                        .unwrap_or("").trim().to_string();

                    let mut issues = vec![];
                    if !has_http_only && !has_secure {
                        issues.push("HttpOnly and Secure flags not detected");
                    }
                    if !has_same_site {
                        issues.push("SameSite cookie attribute not detected");
                    }

                    if !issues.is_empty() {
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.clone(),
                            problem: format!(
                                "Cookie/session configuration: {}. CWE-614/CWE-1004: \
                                Without HttpOnly, cookies are accessible via JavaScript \
                                (XSS theft). Without Secure flag, cookies sent over HTTP \
                                (MITM theft). Without SameSite, cookies vulnerable to CSRF.",
                                issues.join("; ")
                            ),
                            fix_hint: "Always configure cookies with: \
                                cookie.setHttpOnly(true); // block JS access \
                                cookie.setSecure(true); // HTTPS only \
                                cookie.setPath(\"/\"); \
                                For SameSite (Servlet 5.0+/Jakarta): \
                                response.addHeader(\"Set-Cookie\", \"name=value; SameSite=Strict\"); \
                                Or use SameSite attribute in cookie constructor."
                                .to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-020: Unsafe YAML Deserialization
// CWE-502 — CVSS 8.1 — HIGH
// AI generates: yaml.load(input) instead of yaml.safeLoad
// SnakeYAML can execute arbitrary constructors (CVE-2022-1471 pattern)
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaYamlDeserialization;

impl LangRule for JavaYamlDeserialization {
    fn id(&self) -> &str { "JAVA-SEC-020" }
    fn name(&self) -> &str { "Unsafe YAML Deserialization" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let yaml_imports = [
            "org.yaml.snakeyaml.", "snakeyaml.", "Yaml",
        ];

        let yaml_methods: HashSet<&str> = [
            "Yaml.load", "yaml.load", "new Yaml",
            "Yaml.loadAll", "yaml.loadAll",
        ].into_iter().collect();

        let has_yaml = has_import(tree, &yaml_imports);

        if has_yaml {
            for call in &tree.calls {
                if yaml_methods.iter().any(|m| call.callee.contains(m)) {
                    let is_unsafe = call.callee.contains(".load(")
                        || call.callee.contains("new Yaml")
                        || (call.callee.contains("load") && !call.callee.contains("safe"));

                    if is_unsafe {
                        let is_user_input = !call.arguments.is_empty()
                            && call.arguments.iter().any(|a| {
                                a.contains("request") || a.contains("input")
                                    || a.contains("body") || a.contains("param")
                            });

                        let (start, end) = get_line_offsets(code, call.start_line);
                        let line_text = code.lines().nth(call.start_line.saturating_sub(1))
                            .unwrap_or("").trim().to_string();

                        let severity = if is_user_input { "critical" } else { self.severity() };

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: severity.to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.clone(),
                            problem: format!(
                                "Unsafe YAML deserialization: '{}'. CWE-502: SnakeYAML's \
                                Yaml.load() can instantiate arbitrary Java objects via \
                                class constructor, leading to RCE (similar to CVE-2022-1471 \
                                pattern). AI-generated YAML parsing code often uses unsafe load().",
                                line_text.trim()
                            ),
                            fix_hint: "Use Yaml.loadStream() or Yaml.loadAll() with \
                                SafeConstructor and RestrictedSchema. NEVER use Yaml.load() \
                                on untrusted input. Example: \
                                Yaml yaml = new Yaml(new SafeConstructor()); \
                                Or limit to primitive types: SafeConstructor only."
                                .to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-AI-001: Slopsquatting (AI-Hallucinated Dependencies)
// ─────────────────────────────────────────────────────────────────────────────

pub struct JavaSlopsquatting;

impl LangRule for JavaSlopsquatting {
    fn id(&self) -> &str { "JAVA-AI-001" }
    fn name(&self) -> &str { "AI-Hallucinated Dependency (Slopsquatting)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let hallucinated: Vec<&str> = vec![
            "fakerlib", "mockito-fake", "commons-codec-fake",
            "gson-hacked", "fastjson-fork", "spring-boot-test-fake",
            "test-pkg-xyz", "jackson-fork",
        ];
        for imp in &tree.imports {
            for fake in &hallucinated {
                if imp.module.contains(fake) || imp.name.contains(fake) {
                    let (start, end) = get_line_offsets(_code, imp.start_line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: imp.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: imp.module.clone(),
                        problem: format!("Slopsquatting Risk: The package '{}' appears to be a hallucinated name.", imp.module),
                        fix_hint: "Verify this package exists on Maven Central before using.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-AI-002: Verbose Error Exposure
// ─────────────────────────────────────────────────────────────────────────────

pub struct JavaVerboseError;

impl LangRule for JavaVerboseError {
    fn id(&self) -> &str { "JAVA-AI-002" }
    fn name(&self) -> &str { "Verbose Error Exposure" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r#"e\.printStackTrace\s*\("#, "printStackTrace exposing full stack trace"),
            (r#"throw\s+new\s+(Runtime)?Exception\s*\(\s*e\.getMessage\s*\(\)"#, "Exception with message from another exception"),
            (r#"response\.getWriter\(\)\.print\s*\(\s*e\."#, "Direct error output to HTTP response"),
            (r#"ModelAndView\s*\([^)]*Exception[^)]*\)\s*\.addObject\s*\(\s*['\"]error"#, "Error object passed to view without sanitization"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Log error details server-side, return generic message to client.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-AI-003: Missing Input Validation
// ─────────────────────────────────────────────────────────────────────────────

pub struct JavaMissingInputValidation;

impl LangRule for JavaMissingInputValidation {
    fn id(&self) -> &str { "JAVA-AI-003" }
    fn name(&self) -> &str { "Missing Input Validation" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r#"(request|HttpServletRequest)\.getParameter\s*\([^)]+\)\s*(?!.*validate)(?!.*sanitize)(?!.*check)"#, "getParameter without validation"),
            (r#"@RequestParam\s*\([^)]*\)\s+String\s+\w+\s*(?!.*required)"#, "Optional @RequestParam without validation"),
            (r#"ObjectMapper\(\)\.readValue[^)]*\w+\.getInputStream\(\)"#, "Deserializing user input without type checking"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Validate all user input using Bean Validation (@NotNull, @Size) or custom validators.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-AI-004: AI-Generated Code Marker
// ─────────────────────────────────────────────────────────────────────────────

pub struct JavaAiGenComment;

impl LangRule for JavaAiGenComment {
    fn id(&self) -> &str { "JAVA-AI-004" }
    fn name(&self) -> &str { "AI-Generated Code Marker" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"(?i)generated by (chatgpt|claude|copilot|gemini|llm|gpt|ai|openai|anthropic)"##, "AI generation marker"),
            (r##"(?i)written by (chatgpt|claude|copilot|gemini|llm)"##, "AI authorship claim"),
            (r##"(?i)code generated by (cursor|github|replit)"##, "Code assistant marker"),
            (r##"(?i)AI[_-]?generated"##, "AI-generated marker"),
        ];
        for comment in &tree.comments {
            for (pattern, _) in &patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if re.is_match(&comment.text) {
                        let (start, end) = get_line_offsets(code, comment.start_line);
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: comment.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: comment.text.clone(),
                            problem: "AI-Generated Code Detected".to_string(),
                            fix_hint: "Review AI-generated code carefully before production use.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-021: Cross-Site Scripting / XSS (CWE-79)
// Severity: critical | OWASP A03:2021
// response.getWriter().write(), out.println() with user data
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaXss;

impl LangRule for JavaXss {
    fn id(&self) -> &str { "JAVA-SEC-021" }
    fn name(&self) -> &str { "Cross-Site Scripting (XSS)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let xss_patterns = [
            (r##"response\.getWriter\(\)\.write\s*\("##, "Direct write to response with potentially user-controlled data"),
            (r##"out\.print(?:ln)?\s*\(\s*[^)]*(?:request|param|body|session)\."##, "Direct output of user-controlled data"),
            (r##"\${[^}]*(?:param|request|body)[^}]*}"##, "JSP EL expression with user input in output"),
            (r##"<%=\s*[^%]*request\."##, "JSP scriptlet outputting user data"),
            (r##"\.setContentType\s*\(\s*['\"]text/html['\"]\s*\).*?\.write"##, "HTML response writing with user data"),
        ];

        let xss_sinks: HashSet<&str> = [
            "getWriter", "println", "print", "write",
            "getOutputStream", "setContentType",
        ].into_iter().collect();

        for call in &tree.calls {
            if xss_sinks.contains(call.callee.as_str()) {
                let has_user_input = call.arguments.iter().any(|a| {
                    let user_srcs = ["request", "param", "body", "session", "header"];
                    user_srcs.iter().any(|s| a.to_lowercase().contains(s))
                });

                if has_user_input {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = code.lines().nth(call.start_line - 1).unwrap_or("");
                    findings.push(LangFinding {
                        rule_id: "JAVA-SEC-021".to_string(),
                        severity: "critical".to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: "Cross-Site Scripting (XSS): user-controlled data is written directly to HTTP response without encoding.".to_string(),
                        fix_hint: "Encode user output with ESAPI.encoder().encodeForHTML() or use a template engine with auto-escaping (Thymeleaf, Mustache). Never reflect raw user input in HTML responses.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        // Regex-based detection for JSP patterns
        for (pat, problem) in &xss_patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = code.lines().nth(line - 1).unwrap_or("");
                    if !findings.iter().any(|f: &LangFinding| f.line == line) {
                        findings.push(LangFinding {
                            rule_id: "JAVA-SEC-021".to_string(),
                            severity: "critical".to_string(),
                            line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.trim().to_string(),
                            problem: problem.to_string(),
                            fix_hint: "Encode output with OWASP ESAPI or framework-provided encoding. Use Thymeleaf templates with th:text instead of th:utext.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-022: Improper Authentication (CWE-287)
// Severity: high | OWASP A07:2021
// @PostMapping without @PreAuthorize, missing @AuthenticationPrincipal
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaMissingAuth;

impl LangRule for JavaMissingAuth {
    fn id(&self) -> &str { "JAVA-SEC-022" }
    fn name(&self) -> &str { "Improper Authentication / Missing Auth on Endpoint" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let auth_annotations = [
            "PreAuthorize", "Secured", "RolesAllowed",
            "AuthenticationPrincipal", "Authenticated",
        ];

        let sensitive_patterns = [
            (r##"@PostMapping|@GetMapping|@PutMapping|@DeleteMapping|@RequestMapping"##, "HTTP endpoint"),
        ];

        let has_auth = auth_annotations.iter().any(|a| {
            Regex::new(&format!(r"(?i)@{}", a)).map(|re| re.is_match(code)).unwrap_or(false)
        });

        // Only flag if there's no auth at all in the file
        if !has_auth {
            for (pat, label) in &sensitive_patterns {
                if let Ok(re) = Regex::new(pat) {
                    for m in re.find_iter(code) {
                        let line = code[..m.start()].matches('\n').count() + 1;
                        let line_text = code.lines().nth(line - 1).unwrap_or("");
                        findings.push(LangFinding {
                            rule_id: "JAVA-SEC-022".to_string(),
                            severity: "high".to_string(),
                            line,
                            column: 0,
                            start_byte: 0,
                            end_byte: 0,
                            snippet: line_text.trim().to_string(),
                            problem: format!("REST endpoint ({}) without any authentication or authorization annotation detected. This endpoint may be accessible to unauthenticated users.", label),
                            fix_hint: "Add @PreAuthorize('isAuthenticated()') or @Secured({'ROLE_USER'}) annotation. Consider using Spring Security to protect this endpoint.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-023: CSRF Protection Missing (CWE-352)
// Severity: medium | OWASP A01:2021
// @PostMapping without @csrf or CSRF token verification
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaCsrfMissing;

impl LangRule for JavaCsrfMissing {
    fn id(&self) -> &str { "JAVA-SEC-023" }
    fn name(&self) -> &str { "Missing CSRF Protection on State-Changing Endpoints" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let csrf_patterns = [
            r##"(?i)@CsrfToken|@EnableCsrf|csrf\.enabled\s*=\s*false"##,
            r##"(?i)csrf\s*=\s*(?:false|disabled)"##,
        ];

        let has_csrf = csrf_patterns.iter().any(|p| {
            Regex::new(p).map(|re| re.is_match(code)).unwrap_or(false)
        });

        let has_csrf_disabled = Regex::new(r"(?i)csrf\s*=\s*false")
            .map(|re| re.is_match(code)).unwrap_or(false);

        if has_csrf_disabled {
            return findings;
        }

        let state_changing = ["@PostMapping", "@PutMapping", "@DeleteMapping", "@PatchMapping"];

        for call in &tree.calls {
            let call_str = format!("{}()", call.callee);
            for marker in &state_changing {
                if call_str.contains(marker) || call.callee.contains(marker) {
                    if !has_csrf {
                        let (start, end) = get_line_offsets(code, call.start_line);
                        let line_text = code.lines().nth(call.start_line - 1).unwrap_or("");
                        findings.push(LangFinding {
                            rule_id: "JAVA-SEC-023".to_string(),
                            severity: "medium".to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.trim().to_string(),
                            problem: "State-changing endpoint (@PostMapping, @PutMapping, etc.) without explicit CSRF protection. This can enable Cross-Site Request Forgery attacks.".to_string(),
                            fix_hint: "Enable CSRF in Spring Security: http.csrf(). Enable for stateless APIs: http.csrf().ignoringAntMatchers('/api/**'). Or use token-based CSRF via @CsrfToken.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-024: IDOR - Insecure Direct Object Reference (CWE-639)
// Severity: high | OWASP A01:2021
// @PathVariable user-controlled IDs without ownership validation
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaIdor;

impl LangRule for JavaIdor {
    fn id(&self) -> &str { "JAVA-SEC-024" }
    fn name(&self) -> &str { "Insecure Direct Object Reference (IDOR)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Detect @PathVariable usage (user-controlled resource IDs)
        let path_var_re = Regex::new(r##"@PathVariable\s*\("##).unwrap();
        // Detect ownership checks
        let ownership_re = Regex::new(
            r##"(?i)(?:currentUser|principal|auth|owner|belongsTo|isOwner|hasAccess|authorize)"##
        ).unwrap();

        for call in &tree.calls {
            // Look for repository/service calls with path variable
            let service_patterns = ["Repository", "Service", "Dao", "findById", "getById", "delete", "update"];
            let has_path_var = path_var_re.is_match(code);

            if has_path_var && call.arguments.iter().any(|a| a.contains("PathVariable") || a.contains("id") || a.contains("Id")) {
                let has_ownership_check = ownership_re.is_match(code);

                if !has_ownership_check {
                    let line_text = code.lines().nth(call.start_line - 1).unwrap_or("");
                    findings.push(LangFinding {
                        rule_id: "JAVA-SEC-024".to_string(),
                        severity: "high".to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "IDOR risk: @PathVariable used to access a resource without explicit ownership validation. An attacker can enumerate resource IDs to access other users' data.".to_string(),
                        fix_hint: "Always validate resource ownership: if (!resource.getOwner().equals(currentUser)) throw new AccessDeniedException(). Use @PreAuthorize('hasAccess(#id)') with custom security expressions.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        // Also detect patterns where ID is passed directly from request to DB
        let idor_pattern = Regex::new(
            r##"(?i)(?:findById|getById|findByIdOrThrow)\s*\([^)]*(?:PathVariable|@Param).*(?:\.(?:getRepository|find|findById))"##
        ).unwrap();

        if idor_pattern.is_match(code) && !ownership_re.is_match(code) {
            for m in idor_pattern.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let line_text = code.lines().nth(line - 1).unwrap_or("");
                if !findings.iter().any(|f: &LangFinding| f.line == line) {
                    findings.push(LangFinding {
                        rule_id: "JAVA-SEC-024".to_string(),
                        severity: "high".to_string(),
                        line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "Potential IDOR: resource ID from URL path used directly in database query without ownership check.".to_string(),
                        fix_hint: "Add ownership validation: verify the returned resource belongs to the authenticated user before returning it.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-025: XML External Entity (XXE)
// Severity: high | CWE-611
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaXxeExternalEntity;

impl LangRule for JavaXxeExternalEntity {
    fn id(&self) -> &str { "JAVA-SEC-025" }
    fn name(&self) -> &str { "XML External Entity (XXE)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["DocumentBuilder", "SAXParser", "XMLStreamReader", "DOMReader", "XMLInputFactory"];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "XML parser without XXE protection. External entities can be resolved.".to_string(),
                    fix_hint: "Disable DTD and external entities in XML parsers.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-026: SQL Injection via JPA Native Query
// Severity: critical | CWE-89
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaJpaSqlInjection;

impl LangRule for JavaJpaSqlInjection {
    fn id(&self) -> &str { "JAVA-SEC-026" }
    fn name(&self) -> &str { "SQL Injection via JPA Native Query" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let sql_funcs = ["createNativeQuery", "createQuery", "executeUpdate", "executeQuery"];
        for call in &tree.calls {
            if sql_funcs.iter().any(|f| call.callee.contains(f)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("+") || args_str.contains("String.format") || args_str.contains("concat") {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "SQL query built with string concatenation. SQL injection risk.".to_string(),
                        fix_hint: "Use parameterized queries.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-027: Path Traversal
// Severity: high | CWE-22
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaPathTraversalExternal;

impl LangRule for JavaPathTraversalExternal {
    fn id(&self) -> &str { "JAVA-SEC-027" }
    fn name(&self) -> &str { "Path Traversal" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["FileInputStream", "FileReader", "FileOutputStream", "new File", "Paths.get", "Path.of"];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("request") || args_str.contains("param") || args_str.contains("input") {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "File operation with user-controlled path.".to_string(),
                        fix_hint: "Validate and sanitize path input. Use Path.normalize() and resolve against a base directory.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-028: LDAP Injection
// Severity: high | CWE-90
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaLdapInjectionExternal;

impl LangRule for JavaLdapInjectionExternal {
    fn id(&self) -> &str { "JAVA-SEC-028" }
    fn name(&self) -> &str { "LDAP Injection" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["InitialDirContext", "DirContext.lookup", "Context.lookup"];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("request") || args_str.contains("param") || args_str.contains("user") {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "JNDI/LDAP lookup with user-controlled input.".to_string(),
                        fix_hint: "Validate and escape LDAP special characters.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-029: JNDI Injection / Log4Shell
// Severity: critical | CWE-94
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaJndiInjectionLog4Shell;

impl LangRule for JavaJndiInjectionLog4Shell {
    fn id(&self) -> &str { "JAVA-SEC-029" }
    fn name(&self) -> &str { "JNDI Injection / Log4Shell Pattern" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = ["jndi:", "InitialContext", "Context.lookup"];
        for call in &tree.calls {
            if patterns.iter().any(|p| call.callee.contains(p)) || call.arguments.join(" ").contains("jndi:") {
                let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "JNDI lookup detected. Vulnerable to Log4Shell-style attacks.".to_string(),
                    fix_hint: "Upgrade Log4j to 2.17+. Disable JNDI lookups.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-030: Weak Cryptography
// Severity: high | CWE-327
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaWeakCryptoExternal;

impl LangRule for JavaWeakCryptoExternal {
    fn id(&self) -> &str { "JAVA-SEC-030" }
    fn name(&self) -> &str { "Weak Cryptography Usage" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["DES", "DESede", "Blowfish", "RC2", "RC4", "MD5", "SHA1", "getInstance(\"MD5\"", "getInstance(\"SHA-1\""];
        for call in &tree.calls {
            let args_str = call.arguments.join(" ");
            if dangerous.iter().any(|d| call.callee.contains(d)) || (call.callee.contains("Cipher.getInstance") && (args_str.contains("DES") || args_str.contains("RC4") || args_str.contains("MD5"))) {
                let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "Weak cryptographic algorithm (DES/MD5/SHA1/RC4) detected.".to_string(),
                    fix_hint: "Use AES-256-GCM for encryption, SHA-256 for hashing.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-031: Hardcoded Credentials
// Severity: high | CWE-798
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaHardcodedCredentials;

impl LangRule for JavaHardcodedCredentials {
    fn id(&self) -> &str { "JAVA-SEC-031" }
    fn name(&self) -> &str { "Hardcoded Credentials" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for call in &tree.calls {
            if call.callee.contains("setPassword") || call.callee.contains("setProperty") {
                let args_str = call.arguments.join(" ");
                let secret_patterns = ["password", "secret", "apikey", "api_key", "token", "credential"];
                if secret_patterns.iter().any(|p| args_str.to_lowercase().contains(p)) {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "Hardcoded credentials in source code.".to_string(),
                        fix_hint: "Use environment variables: System.getenv(\"DB_PASSWORD\").".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-032: Serialization Gadget
// Severity: critical | CWE-502
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaSerializationGadget;

impl LangRule for JavaSerializationGadget {
    fn id(&self) -> &str { "JAVA-SEC-032" }
    fn name(&self) -> &str { "Deserialization Gadget Risk" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["ObjectInputStream", "readObject", "XMLDecoder", "XStream.fromXML"];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "Deserialization of untrusted data can lead to RCE.".to_string(),
                    fix_hint: "Use JSON serializers (Jackson, Gson) instead of Java serialization.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-033: XML Bomb / Billion Laughs
// Severity: high | CWE-400
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaXmlBomb;

impl LangRule for JavaXmlBomb {
    fn id(&self) -> &str { "JAVA-SEC-033" }
    fn name(&self) -> &str { "XML Bomb / Billion Laughs Attack" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let xml_parsers = ["SAXParserFactory.newInstance", "DocumentBuilderFactory.newInstance", "XMLInputFactory.newInstance", "TransformerFactory.newInstance"];
        for call in &tree.calls {
            if xml_parsers.iter().any(|p| call.callee.contains(p)) {
                let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "XML parser without entity expansion limits. Vulnerable to billion laughs.".to_string(),
                    fix_hint: "Limit entity expansion in XML parsers.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-034: SSRF - Internal Metadata
// Severity: medium | CWE-918
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaSsrfInternal;

impl LangRule for JavaSsrfInternal {
    fn id(&self) -> &str { "JAVA-SEC-034" }
    fn name(&self) -> &str { "SSRF - Cloud Metadata Access" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = ["169.254.169.254", "metadata.google.internal", "metadata.azure.com", "kubernetes.docker.internal"];
        for call in &tree.calls {
            let args_str = call.arguments.join(" ");
            if patterns.iter().any(|p| args_str.contains(p)) {
                let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "HTTP request to internal cloud metadata. SSRF vulnerability.".to_string(),
                    fix_hint: "Block access to internal IP ranges and cloud metadata endpoints.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-035: Insecure Random Number Generator
// Severity: medium | CWE-338
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaInsecureRandom;

impl LangRule for JavaInsecureRandom {
    fn id(&self) -> &str { "JAVA-SEC-035" }
    fn name(&self) -> &str { "Insecure Random Number Generator" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for call in &tree.calls {
            if call.callee.contains("new Random()") || call.callee.contains("java.util.Random") {
                let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "java.util.Random is predictable and not suitable for security purposes.".to_string(),
                    fix_hint: "Use java.security.SecureRandom for security-sensitive randomness.".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-AI-005: AI Hardcoded Credentials
// Severity: high | CWE-798
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaAiHardcodedCredentials;

impl LangRule for JavaAiHardcodedCredentials {
    fn id(&self) -> &str { "JAVA-AI-005" }
    fn name(&self) -> &str { "AI: Hardcoded Credentials" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)password\s*[=:]\s*["'][^'"]{4,}["']"##, "Hardcoded password"),
            (r##"(?i)api[_-]?key\s*[=:]\s*["'][A-Za-z0-9_\-]{8,}["']"##, "Hardcoded API key"),
        ];
        for (pat, desc) in &patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("AI-generated code contains hardcoded {}: credentials exposed.", desc),
                        fix_hint: "Move to environment variables or a secrets manager.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-AI-006: AI SQL Injection via String Concatenation
// Severity: critical | CWE-89
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaAiSqlInjection;

impl LangRule for JavaAiSqlInjection {
    fn id(&self) -> &str { "JAVA-AI-006" }
    fn name(&self) -> &str { "AI: SQL Injection via String Concatenation" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let sql_funcs = ["Statement.execute", "Statement.executeQuery", "createQuery", "createNativeQuery"];
        for call in &tree.calls {
            if sql_funcs.iter().any(|f| call.callee.contains(f)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("+") || args_str.contains("String.format") {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "AI-generated SQL query with string concatenation.".to_string(),
                        fix_hint: "Use parameterized queries with PreparedStatement.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-AI-007: AI Command Injection
// Severity: critical | CWE-78
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaAiCommandInjection;

impl LangRule for JavaAiCommandInjection {
    fn id(&self) -> &str { "JAVA-AI-007" }
    fn name(&self) -> &str { "AI: Command Injection via Runtime.exec()" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["Runtime.getRuntime().exec", "ProcessBuilder"];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("request") || args_str.contains("param") || args_str.contains("user") {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "AI-generated command execution with user-controlled input.".to_string(),
                        fix_hint: "Avoid Runtime.exec() with user input. Validate against allowlist.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-AI-008: AI XXE via DocumentBuilder
// Severity: high | CWE-611
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaAiXxe;

impl LangRule for JavaAiXxe {
    fn id(&self) -> &str { "JAVA-AI-008" }
    fn name(&self) -> &str { "AI: XXE via DocumentBuilder" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["DocumentBuilderFactory.newInstance", "SAXParserFactory.newInstance"];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: line_text.trim().to_string(),
                    problem: "AI-generated XML parser without XXE protection.".to_string(),
                    fix_hint: "Disable XXE: factory.setFeature(XMLConstants.ACCESS_EXTERNAL_DTD, \"\");".to_string(),
                    auto_fix_available: false,
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-036: Deep SSRF Detection with User Input and Internal IP Ranges
// Severity: high | CWE-918
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaSsrfDeep;

impl LangRule for JavaSsrfDeep {
    fn id(&self) -> &str { "JAVA-SEC-036" }
    fn name(&self) -> &str { "SSRF: Deep Detection with User Input and Internal IPs" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let ssrf_targets: HashSet<&str> = [
            "HttpClient.newBuilder",
            "HttpClient.send",
            "HttpURLConnection",
            "RestTemplate.getForObject",
            "RestTemplate.postForObject",
            "RestTemplate.putForObject",
            "RestTemplate.deleteForObject",
            "RestTemplate.patchForObject",
            "WebClient.create",
            "WebClient.builder",
            "URLConnection.connect",
            "URLConnection.getInputStream",
            "new URL",
            "URL.openConnection",
            "HttpRequest.newBuilder",
            "HttpResponse.send",
        ].into_iter().collect();

        let user_input_patterns: Vec<&str> = vec![
            "@RequestParam",
            "@PathVariable",
            "@RequestBody",
            "request.getParameter",
            "request.getQueryString",
            "request.getHeader",
            "request.getInputStream",
            "request.getReader",
            "params.get",
            "query.get",
            "body.get",
            "form.get",
            "HttpServletRequest.getParameter",
            "HttpServletRequest.getQueryString",
            "HttpServletRequest.getHeader",
            "HttpServletRequest.getInputStream",
        ];

        let internal_ip_patterns: Vec<&str> = vec![
            "169.254.169.254",
            "169.254.169.253",
            "127.0.0.1",
            "localhost",
            "0.0.0.0",
            "metadata.google.internal",
            "metadata.azure.com",
        ];

        for call in &tree.calls {
            if !ssrf_targets.iter().any(|t| call.callee.contains(t)) {
                continue;
            }

            let args_str = call.arguments.join(" ");

            let has_user_input = user_input_patterns.iter().any(|p| args_str.contains(p));
            let has_internal_ip = internal_ip_patterns.iter().any(|p| args_str.contains(p));

            if has_user_input || has_internal_ip {
                let (start, end) = get_line_offsets(code, call.start_line);
                let line_text = get_line_text(code, call.start_line).unwrap_or_default();

                let problem = if has_internal_ip {
                    format!(
                        "SSRF risk: '{}' uses internal IP range or cloud metadata endpoint. \
                        CWE-918: Attackers may access internal resources, cloud metadata (AWS 169.254.169.254), \
                        or local services.",
                        call.callee
                    )
                } else {
                    format!(
                        "SSRF risk: '{}' uses URL derived from user-controlled input. \
                        CWE-918: Without proper validation, attackers can make the server request \
                        arbitrary URLs, internal services, or cloud metadata endpoints.",
                        call.callee
                    )
                };

                let fix_hint = if has_internal_ip {
                    "Block access to internal IP ranges and cloud metadata endpoints. \
                    Add IP allowlist validation before making requests.".to_string()
                } else {
                    "Validate URLs against an allowlist of permitted domains and schemes. \
                    Block internal IP ranges and cloud metadata endpoints (169.254.0.0/16). \
                    Example: URLValidator.validate(url, ALLOWED_HOSTS)".to_string()
                };

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem,
                    fix_hint,
                    auto_fix_available: false,
                });
            }
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── JAVA-AI-009: Typo-Squatted Java Package Import ───────────────────────────

pub struct JavaSlopsquattingTypo;

impl LangRule for JavaSlopsquattingTypo {
    fn id(&self) -> &str { "JAVA-AI-009" }
    fn name(&self) -> &str { "Typo-Squatted Java Package Import" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let typo_patterns: Vec<(&str, &str, &str)> = vec![
            // java.util typos
            (r##"import\s+java\.utile"##, "java.util", "Possible typo-squat of 'java.util' package"),
            (r##"import\s+java\.uitl"##, "java.util", "Possible typo-squat of 'java.util' package"),
            (r##"import\s+java\.uil"##, "java.util", "Possible typo-squat of 'java.util' package"),
            (r##"import\s+java\.utl"##, "java.util", "Possible typo-squat of 'java.util' package"),
            // java.io typos
            (r##"import\s+java\.oi"##, "java.io", "Possible typo-squat of 'java.io' package"),
            (r##"import\s+java\.ioo"##, "java.io", "Possible typo-squat of 'java.io' package"),
            // org.springframework typos
            (r##"import\s+org\.springframwork"##, "org.springframework", "Possible typo-squat of 'org.springframework' package"),
            (r##"import\s+org\.springfrmework"##, "org.springframework", "Possible typo-squat of 'org.springframework' package"),
            (r##"import\s+org\.sprngframework"##, "org.springframework", "Possible typo-squat of 'org.springframework' package"),
            (r##"import\s+org\.springframerwork"##, "org.springframework", "Possible typo-squat of 'org.springframework' package"),
            // org.apache.commons typos
            (r##"import\s+org\.apache\.common"##, "org.apache.commons", "Possible typo-squat of 'org.apache.commons' package"),
            (r##"import\s+org\.apache\.commns"##, "org.apache.commons", "Possible typo-squat of 'org.apache.commons' package"),
            (r##"import\s+org\.apche\.commons"##, "org.apache.commons", "Possible typo-squat of 'org.apache.commons' package"),
            (r##"import\s+org\.apache\.commos"##, "org.apache.commons", "Possible typo-squat of 'org.apache.commons' package"),
            // com.google.guava typos
            (r##"import\s+com\.gogle\.guava"##, "com.google.guava", "Possible typo-squat of 'com.google.guava' package"),
            (r##"import\s+com\.googel\.guava"##, "com.google.guava", "Possible typo-squat of 'com.google.guava' package"),
            (r##"import\s+com\.google\.guava"##, "com.google.guava", "Possible typo-squat of 'com.google.guava' package"),
            (r##"import\s+com\.googl\.guava"##, "com.google.guava", "Possible typo-squat of 'com.google.guava' package"),
            // io.jsonwebtoken typos
            (r##"import\s+io\.jsonwebtokn"##, "io.jsonwebtoken", "Possible typo-squat of 'io.jsonwebtoken' package"),
            (r##"import\s+io\.jsonwebtken"##, "io.jsonwebtoken", "Possible typo-squat of 'io.jsonwebtoken' package"),
            (r##"import\s+io\.jsonwebtoke"##, "io.jsonwebtoken", "Possible typo-squat of 'io.jsonwebtoken' package"),
            // com.fasterxml.jackson typos
            (r##"import\s+com\.fasterxml\.jakson"##, "com.fasterxml.jackson", "Possible typo-squat of 'com.fasterxml.jackson' package"),
            (r##"import\s+com\.fasterxml\.jkson"##, "com.fasterxml.jackson", "Possible typo-squat of 'com.fasterxml.jackson' package"),
            (r##"import\s+com\.fasterxml\.jackson"##, "com.fasterxml.jackson", "Possible typo-squat of 'com.fasterxml.jackson' package"),
        ];

        for (pattern, _canonical, desc) in &typo_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("Slopsquatting Risk: {}", desc),
                        fix_hint: "Verify this package exists in Maven Central or official repositories before using.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        // Check for typosquatting keywords in package imports
        let keyword_patterns: Vec<(&str, &str)> = vec![
            (r##"import\s+[a-z]+\.[a-z]+\.[a-z]+\.(typo|demo|test|lib|utils|helper)"##, "Package import with typosquatting keyword"),
            (r##"import\s+com\.(typo|demo|test|lib|utils|helper)\."##, "Package import with typosquatting keyword in domain"),
            (r##"import\s+org\.(typo|demo|test|lib|utils|helper)\."##, "Package import with typosquatting keyword in org"),
        ];

        for (pattern, desc) in &keyword_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("Slopsquatting Risk: {} in import statement", desc),
                        fix_hint: "Verify this package exists in Maven Central or official repositories before using.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-037: Weak JWT Verification
// Severity: critical | CWE-345
// Jwts.parser().setSigningKey(null), Algorithm.NONE, etc.
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaWeakJwt;

impl LangRule for JavaWeakJwt {
    fn id(&self) -> &str { "JAVA-SEC-037" }
    fn name(&self) -> &str { "Weak JWT Verification" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r#"Jwts\.parser\(\)\.setSigningKey\s*\(\s*null\s*\)"#, "JWT parser with null signing key - no verification"),
            (r#"Jwts\.parser\(\)\.setSigningKey\s*\(\s*""\s*\)"#, "JWT parser with empty signing key"),
            (r#"Jwts\.parserBuilder\(\)\.setSigningKey\s*\(\s*null\s*\)"#, "JWT parserBuilder with null signing key"),
            (r#"Jwts\.parserBuilder\(\)\.setSigningKey\s*\(\s*""\s*\)"#, "JWT parserBuilder with empty signing key"),
            (r#"Key\.getInstance\s*\(\s*["']none["']"#, "JWT with 'none' algorithm - no signature verification"),
            (r#"Algorithm\.NONE"#, "Algorithm.NONE used for JWT - disables signature verification"),
            (r#"Jwts\.parser\(\)\.verifyWith\s*\(\s*null\s*\)"#, "JWT parser with verifyWith(null)"),
            (r#"new SecretKeySpec\s*\(\s*new\s+byte\s*\[\s*0\s*\]\s*,"#, "SecretKeySpec with zero-length key"),
            (r#"Jwts\.parser\(\)\.verifyWith\s*\(\s*new\s+SecretKeySpec\s*\(\s*new\s+byte\s*\[\s*0\s*\]\s*,"#, "JWT verification with empty key"),
        ];

        for (pat, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("Weak JWT verification: {}. Tokens can be forged without proper signature verification.", problem),
                        fix_hint: "Use a strong, secret key (minimum 256 bits for HS256). Retrieve the key securely (e.g., from environment variable or secrets manager). Always verify the signing key is present and valid.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-CRYPT-001: Insecure Cryptography in Java
// Severity: critical | CWE-327, CWE-295
// Detects insecure cryptographic practices in Java code
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaInsecureCrypto;

impl LangRule for JavaInsecureCrypto {
    fn id(&self) -> &str { "JAVA-CRYPT-001" }
    fn name(&self) -> &str { "Insecure Cryptographic Practices" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Insecure SSL/TLS protocols
        let tls_patterns = [
            (r#"SSLContext\.getInstance\s*\(\s*["']TLSv1\.0["']\s*\)"#, "SSLContext with TLSv1.0 - deprecated protocol"),
            (r#"SSLContext\.getInstance\s*\(\s*["']SSL["']\s*\)"#, "SSLContext with 'SSL' - uses deprecated SSL protocol"),
            (r#"SSLContext\.getInstance\s*\(\s*["']SSLv3["']\s*\)"#, "SSLContext with SSLv3 - vulnerable to POODLE"),
            (r#"SSLContext\.getInstance\s*\(\s*["']TLSv1\.1["']\s*\)"#, "SSLContext with TLSv1.1 - deprecated protocol"),
            (r#"setEnabledProtocols\s*\(\s*\[[^]]*"TLSv1\.0"[^]]*\]"#, "TLSv1.0 enabled - deprecated protocol"),
            (r#"setEnabledProtocols\s*\(\s*\[[^]]*"TLSv1\.1"[^]]*\]"#, "TLSv1.1 enabled - deprecated protocol"),
            (r#"setEnabledProtocols\s*\(\s*\[[^]]*"SSLv3"[^]]*\]"#, "SSLv3 enabled - vulnerable to POODLE"),
        ];

        // Insecure cipher modes (ECB, no padding validation)
        let cipher_patterns = [
            (r#"Cipher\.getInstance\s*\(\s*["']AES/ECB/[^"]*PKCS5Padding["']\s*\)"#, "AES/ECB/PKCS5Padding - ECB mode is insecure (patterns visible in ciphertext)"),
            (r#"Cipher\.getInstance\s*\(\s*["']AES/ECB/["']"#, "AES/ECB mode - insecure (no encryption beyond XOR patterns)"),
            (r#"Cipher\.getInstance\s*\(\s*["']DES/ECB/[^"]*["']"#, "DES/ECB mode - insecure (56-bit key, visible patterns)"),
            (r#"Cipher\.getInstance\s*\(\s*["']DES/ECB/PKCS5Padding["']\s*\)"#, "DES/ECB/PKCS5Padding - broken cipher and mode"),
            (r#"Cipher\.getInstance\s*\(\s*["'][^/]+/CBC/["']"#, "CBC mode without authentication - consider GCM"),
        ];

        // Weak key generation
        let keygen_patterns = [
            (r#"KeyGenerator\.getInstance\s*\(\s*["']DES["']\s*\)"#, "KeyGenerator for DES - 56-bit key is trivially broken"),
            (r#"KeyGenerator\.getInstance\s*\(\s*["']AES["']\s*\).*(?i)(?:\.init\s*\(\s*[0-9]{1,3}\s*\))?"#, "AES KeyGenerator - ensure key size is 128+ bits"),
            (r#"KeyPairGenerator\.getInstance\s*\(\s*["']RSA["']\s*\)"#, "RSA KeyPairGenerator - verify key size is 2048+ bits"),
        ];

        // Short key in SecretKeySpec
        let short_key_patterns = [
            (r#"new\s+SecretKeySpec\s*\(\s*[^,]+,\s*["']AES["']\s*\).*(?i)(key\.length\s*<\s*16|key\.length\s*==\s*8)"#, "SecretKeySpec with short key for AES (< 16 bytes)"),
            (r#"new\s+SecretKeySpec\s*\(\s*new\s+byte\s*\[\s*[0-9]{1,2}\s*\]\s*,"#, "SecretKeySpec with very short key - likely insecure"),
        ];

        // Blanket TrustManager (accepts all certs)
        let trust_patterns = [
            (r#"TrustManager\s*\[\s*\]\s*\{\s*new\s+X509TrustManager\s*\{[^}]*checkClientTrusted\s*\(\s*\)\s*\{\s*\}"#, "X509TrustManager with empty checkClientTrusted - accepts all client certs"),
            (r#"TrustManager\s*\[\s*\]\s*\{\s*new\s+X509TrustManager\s*\{[^}]*checkServerTrusted\s*\(\s*\)\s*\{\s*\}"#, "X509TrustManager with empty checkServerTrusted - accepts all server certs"),
            (r#"TrustManager\s*\[\s*\]\s*\{\s*new\s+X509TrustManager\s*\{[^}]*checkValidity\s*\(\s*\)\s*\{\s*\}"#, "X509TrustManager with empty checkValidity - accepts expired certs"),
            (r#"new\s+TrustManagerFactory\([^)]*\).*\.init\s*\(\s*\(TrustManager\[\]\)\s*\{"#, "Custom TrustManager array - verify implementation"),
        ];

        // Process all patterns
        for (pattern, problem) in tls_patterns.iter().chain(cipher_patterns.iter())
            .chain(keygen_patterns.iter()).chain(short_key_patterns.iter())
            .chain(trust_patterns.iter()) {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "Insecure Cryptography: {}. CWE-327/CWE-295: {}",
                            problem,
                            if pattern.contains("SSLContext") || pattern.contains("TLS") {
                                "Using deprecated protocols allows MITM attacks."
                            } else if pattern.contains("ECB") {
                                "ECB mode reveals patterns in ciphertext."
                            } else if pattern.contains("TrustManager") {
                                "Blanket TrustManager allows any certificate."
                            } else {
                                "Weak cryptographic configuration."
                            }
                        ),
                        fix_hint: if pattern.contains("TLS") || pattern.contains("SSL") {
                            "Use TLS 1.2 or higher. Example: SSLContext.getInstance(\"TLSv1.2\");".to_string()
                        } else if pattern.contains("ECB") {
                            "Use AES/GCM or AES/CBC with HMAC. Example: Cipher.getInstance(\"AES/GCM/NoPadding\");".to_string()
                        } else if pattern.contains("TrustManager") {
                            "Use the default TrustManager or implement proper certificate validation.".to_string()
                        } else {
                            "Use strong algorithms and key sizes (AES-256, RSA-2048+).".to_string()
                        },
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-038: SQL Injection via JPA/Hibernate Native Query
// Severity: critical | CWE-89
// Native SQL queries in JPA/Hibernate built with string concatenation
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaJpaNativeSqlInjection;

impl LangRule for JavaJpaNativeSqlInjection {
    fn id(&self) -> &str { "JAVA-SEC-038" }
    fn name(&self) -> &str { "SQL Injection (JPA/Hibernate Native Query)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let jpa_imports = [
            "javax.persistence.", "jakarta.persistence.",
            "org.hibernate.", "org.springframework.data.jpa.",
        ];
        let has_jpa = has_import(tree, &jpa_imports);

        if !has_jpa {
            return findings;
        }

        let dangerous_patterns = vec![
            (r#"createNativeQuery\s*\([^)]*\+\s*(?:req|param|request|input|user)"#, "JPA createNativeQuery with string concatenation of user input"),
            (r#"createQuery\s*\([^)]*\+\s*(?:req|param|request|input|user)"#, "JPA createQuery (HQL) with string concatenation"),
            (r#"createSQLQuery\s*\([^)]*\+\s*(?:req|param|request|input|user)"#, "Hibernate createSQLQuery with string concatenation"),
            (r#"findBySql\s*\([^)]*\+\s*(?:req|param|request|input|user)"#, "Spring Data JPA findBySql with user input"),
            (r#"(?:@Query)\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*\$\{[^}]*(?:req|param|request|input|user)"#, "JPQL @Query with string interpolation of user input"),
            (r#"entityManager\.createNativeQuery\s*\([^)]*\+[^)]*\)"#, "EntityManager native query with concatenation"),
            (r#"session\.createSQLQuery\s*\([^)]*\+[^)]*\)"#, "Hibernate Session createSQLQuery with concatenation"),
        ];

        for (pattern, desc) in &dangerous_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    if findings.iter().any(|f: &LangFinding| f.line == line) {
                        continue;
                    }
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "JPA/Hibernate SQL injection: {}. CWE-89: Native SQL query built with \
                            string concatenation allows attackers to manipulate database queries.",
                            desc
                        ),
                        fix_hint: "Use parameterized queries: entityManager.createNativeQuery(\n                            \"SELECT * FROM users WHERE id = ?\", User.class).setParameter(1, userId);\n                            In Spring Data JPA @Query: @Query(\"SELECT u FROM User u WHERE u.name = :name\")\n                            User findByName(@Param(\"name\") String name);".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-039: Deserialization Gadget Chain
// Severity: critical | CWE-502
// ObjectInputStream with readObject on untrusted data — gadget chains enable RCE
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaDeserializationGadgetChain;

impl LangRule for JavaDeserializationGadgetChain {
    fn id(&self) -> &str { "JAVA-SEC-039" }
    fn name(&self) -> &str { "Deserialization Gadget Chain (readObject)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_patterns = vec![
            (r#"ObjectInputStream\s*\(\s*(?:new|)?(?:FileInputStream|SocketInputStream|ByteArrayInputStream|InputStream)"#, "ObjectInputStream created with untrusted stream — gadget chain RCE risk"),
            (r#"readObject\s*\(\s*\)\s*(?:throws|;)"#, "readObject() called — deserializes untrusted data"),
            (r#"readUnshared\s*\(\s*\)"#, "readUnshared() called — same deserialization risk as readObject"),
            (r#"XMLDecoder\s*\(\s*(?:new|)?(?:FileInputStream|ByteArrayInputStream|Socket)"#, "XMLDecoder with untrusted stream — XML deserialization RCE"),
            (r#"XStream\s*\(\s*\)\s*\.fromXML\s*\([^)]*(?:req|param|request|input|user|body)"#, "XStream.fromXML() with user input — known RCE gadget chain"),
            (r#"readValue\s*\(\s*(?:req|param|request|input|user|body|file)"#, "Jackson/JSON deserialization with user input — potential gadget chain"),
            (r#"yaml\.load\s*\([^)]*(?:req|param|request|input|user|body|file)"#, "SnakeYAML load() with user input — YAML deserialization RCE"),
            // Known gadget chain triggers
            (r#"URL\s*\(\s*(?:req|param|request|input|user)"#, "URL object deserialization — URL gadget chain for DNS/SSRF"),
        ];

        for (pattern, desc) in &dangerous_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    if findings.iter().any(|f: &LangFinding| f.line == line) {
                        continue;
                    }
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "Deserialization gadget chain: {}. CWE-502: ObjectInputStream.readObject() \
                            on untrusted data. Attackers can use known gadget chains (Apache Commons, \
                            Spring, Groovy) to achieve RCE without needing to plant malicious code.",
                            desc
                        ),
                        fix_hint: "Never deserialize untrusted data. Use JSON (Jackson with \
                            enableDefaultTyping disabled) orProtobuf. If deserialization is needed, \
                            use ObjectInputFilter with a whitelist: \
                            ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(\"mypackage.*\");".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-040: LDAP Injection Deep
// Severity: high | CWE-90
// LDAP queries built with string concatenation of user input
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaLdapInjectionDeep;

impl LangRule for JavaLdapInjectionDeep {
    fn id(&self) -> &str { "JAVA-SEC-040" }
    fn name(&self) -> &str { "LDAP Injection Deep" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let ldap_imports = ["javax.naming.", "javax.naming.directory.", "ldap", "org.springframework.security.ldap."];
        let has_ldap = has_import(tree, &ldap_imports);

        if !has_ldap {
            return findings;
        }

        let dangerous_patterns = vec![
            (r#"search\s*\([^)]*\+\s*(?:req|param|request|input|user|username|email)"#, "LDAP search with string concatenation of user input"),
            (r#"search\s*\([^)]*(?:req|param|request|input|user|username|email)[^)]*\+[^)]*\)"#, "LDAP search with user input in filter"),
            (r#"DirContext\.search\s*\([^)]*\+[^)]*\)"#, "DirContext.search with concatenation"),
            (r#"(?:ctx|dirContext|ldapContext)\s*\.\s*search\s*\([^)]*\+[^)]*\+[^)]*\)"#, "LDAP search with multiple concatenated parameters"),
            (r#"new\s+Hashtable\s*\(\s*\)\s*.*?put\s*\(\s*\"java\.naming\.provider\.url\".*?\+.*?req"#, "LDAP context initialized with user-controlled URL"),
        ];

        for (pattern, desc) in &dangerous_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    if findings.iter().any(|f: &LangFinding| f.line == line) {
                        continue;
                    }
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "LDAP injection: {}. CWE-90: User input concatenated into LDAP query \
                            allows attackers to bypass authentication, enumerate directory structure, \
                            or extract sensitive data.",
                            desc
                        ),
                        fix_hint: "Use parameterized LDAP queries with SearchControls. Escape special \
                            characters: DN = escapeDN(username); Filter = escapeFilter(username). \
                            Example: SearchControls sc = new SearchControls(); \
                            sc.setFilterExpr(\"(&(uid={0})(objectClass=person))\"); \
                            ctx.search(base, sc.getFilter(), new Object[]{username}, sc);".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JAVA-SEC-041: Path Traversal Deep (Spring @PathVariable)
// Severity: high | CWE-22
// Spring MVC @PathVariable used directly in file operations without validation
// ─────────────────────────────────────────────────────────────────────────────
pub struct JavaPathTraversalSpring;

impl LangRule for JavaPathTraversalSpring {
    fn id(&self) -> &str { "JAVA-SEC-041" }
    fn name(&self) -> &str { "Path Traversal (Spring @PathVariable)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let spring_imports = ["org.springframework.", "org.springframework.web.bind.annotation.", "javax.servlet.", "jakarta.servlet."];
        let has_spring = has_import(tree, &spring_imports);

        if !has_spring {
            return findings;
        }

        let dangerous_patterns = vec![
            (r#"@GetMapping|@PostMapping|@RequestMapping|@PutMapping|@DeleteMapping""#, "Spring REST endpoint detected — checking for path traversal"),
            (r#"@PathVariable\s+\w+\s+(\w+).*?(?:new\s+File|Paths\.get|Path\.of|Files\.readString|Files\.readAllBytes|Files\.copy|Files\.newBufferedReader)\s*\([^)]*\1"#, "PathVariable parameter used directly in file operation without validation"),
            (r#"@PathVariable.*?(?:filename|file|path|filepath|uri).*?(?:new\s+File|Paths\.get|Path\.of)\s*\([^)]*\$"#, "PathVariable with dangerous name used in file operation"),
            (r#"PathVariable\s+\w+\s+(\w+).*?(?:sendRedirect|forward)\s*\([^)]*\1"#, "PathVariable used in redirect/forward — open redirect via path traversal"),
            (r#"PathVariable.*?(?:template|view|page).*?(?:return|ModelAndView)\s*\(.*?\1"#, "PathVariable used in template/view name — potential path traversal"),
        ];

        for (pattern, desc) in &dangerous_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    if findings.iter().any(|f: &LangFinding| f.line == line) {
                        continue;
                    }
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "Path traversal via @PathVariable: {}. CWE-22: A @PathVariable parameter \
                            (e.g., filename) is used directly in a file operation without sanitization. \
                            Attackers can use ../../etc/passwd to access arbitrary files.",
                            desc
                        ),
                        fix_hint: "Always validate and sanitize @PathVariable values: \
                            String filename = pathVariable.replaceAll(\"[^a-zA-Z0-9._-]\", \"\"); \
                            Path file = baseDir.resolve(filename).normalize(); \
                            if (!file.startsWith(baseDir)) throw new SecurityException();".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// All Java Security Rules
// ─────────────────────────────────────────────────────────────────────────────

/// Returns all Java security rules (for use by JavaScanner).
pub fn java_security_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(JavaDeserializationRCE),
        Box::new(JavaSqlInjection),
        Box::new(JavaXXE),
        Box::new(JavaJndiInjection),
        Box::new(JavaSSRF),
        Box::new(JavaSpELInjection),
        Box::new(JavaHardcodedSecrets),
        Box::new(JavaWeakCrypto),
        Box::new(JavaCommandInjection),
        Box::new(JavaPathTraversal),
        Box::new(JavaSpringSecurityMisconfig),
        Box::new(JavaLogInjection),
        Box::new(JavaLdapInjection),
        Box::new(JavaUnsafeReflection),
        Box::new(JavaMassAssignment),
        Box::new(JavaTemplateInjection),
        Box::new(JavaXMLDecoder),
        Box::new(JavaTypeConfusion),
        Box::new(JavaInsecureCookie),
        Box::new(JavaYamlDeserialization),
        Box::new(JavaSlopsquatting),
        Box::new(JavaVerboseError),
        Box::new(JavaMissingInputValidation),
        Box::new(JavaAiGenComment),
        // New rules JAVA-SEC-021 through JAVA-SEC-024
        Box::new(JavaXss),
        Box::new(JavaMissingAuth),
        Box::new(JavaCsrfMissing),
        Box::new(JavaIdor),
        // New rules JAVA-SEC-025 through JAVA-SEC-035
        Box::new(JavaXxeExternalEntity),
        Box::new(JavaJpaSqlInjection),
        Box::new(JavaPathTraversalExternal),
        Box::new(JavaLdapInjectionExternal),
        Box::new(JavaJndiInjectionLog4Shell),
        Box::new(JavaWeakCryptoExternal),
        Box::new(JavaHardcodedCredentials),
        Box::new(JavaSerializationGadget),
        Box::new(JavaXmlBomb),
        Box::new(JavaSsrfInternal),
        Box::new(JavaInsecureRandom),
        // New rules JAVA-AI-005 through JAVA-AI-008
        Box::new(JavaAiHardcodedCredentials),
        Box::new(JavaAiSqlInjection),
        Box::new(JavaAiCommandInjection),
        Box::new(JavaAiXxe),
        // New rule JAVA-SEC-036
        Box::new(JavaSsrfDeep),
        // JAVA-AI-009: Typo-Squatted Java Package Import
        Box::new(JavaSlopsquattingTypo),
        // New rule JAVA-SEC-037
        Box::new(JavaWeakJwt),
        // JAVA-CRYPT-001: Insecure Cryptography
        Box::new(JavaInsecureCrypto),
        // JAVA-SEC-038 to JAVA-SEC-041: Vulnerable Sink Detection (Reverse-Engineered from hackingtool)
        // JAVA-SEC-038: JPA/Hibernate Native Query SQL Injection
        Box::new(JavaJpaNativeSqlInjection),
        // JAVA-SEC-039: Deserialization Gadget Chain
        Box::new(JavaDeserializationGadgetChain),
        // JAVA-SEC-040: LDAP Injection Deep
        Box::new(JavaLdapInjectionDeep),
        // JAVA-SEC-041: Path Traversal Deep (Spring @PathVariable)
        Box::new(JavaPathTraversalSpring),
    ]
}

