//! PyNEAT Language Server Protocol (LSP) Server
//!
//! Provides real-time security scanning as a Language Server for IDE integration.
//!
//! Usage:
//!     pyneat lsp --stdio
//!
//! This is a minimal stdio-based LSP server that speaks JSON-RPC over stdin/stdout.
#![allow(non_snake_case)]
//! No external LSP crates required — only serde_json for JSON parsing.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// --------------------------------------------------------------------------
// JSON-RPC types
// --------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    #[serde(rename = "jsonrpc")]
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    #[serde(rename = "jsonrpc")]
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    fn ok(id: Value, result: Value) -> Self {
        Self { jsonrpc: "2.0".into(), id, result: Some(result), error: None }
    }
    #[allow(dead_code)]
    fn err(id: Value, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError { code, message: message.into() }),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcNotification {
    #[serde(rename = "jsonrpc")]
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcNotification {
    fn new(method: &str, params: Value) -> Self {
        Self { jsonrpc: "2.0".into(), method: method.into(), params: Some(params) }
    }
}

// --------------------------------------------------------------------------
// LSP types
// --------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct InitializeResult {
    pub capabilities: ServerCapabilities,
    #[serde(skip_serializing_if = "Option::is_none", rename = "serverInfo")]
    pub server_info: Option<ServerInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerCapabilities {
    #[serde(rename = "textDocumentSync", skip_serializing_if = "Option::is_none")]
    pub text_document_sync: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "hoverProvider")]
    pub hover_provider: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "codeActionProvider")]
    pub code_action_provider: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "definitionProvider")]
    pub definition_provider: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TextDocumentItem {
    pub uri: String,
    #[serde(rename = "languageId")]
    pub language_id: String,
    pub version: i32,
    pub text: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DidOpenParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentItem,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DidSaveParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DidChangeParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentItem,
    #[serde(rename = "contentChanges")]
    pub content_changes: Vec<TextDocumentChange>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TextDocumentChange {
    pub text: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HoverParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
    pub position: Position,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextDocumentIdentifier {
    pub uri: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CodeActionParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentIdentifier,
    pub range: Range,
    pub context: CodeActionContext,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CodeActionContext {
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HoverResult {
    pub contents: HoverContents,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum HoverContents {
    Scalar(String),
    Structured(HoverMarkupContent),
}

#[derive(Debug, Clone, Serialize)]
pub struct HoverMarkupContent {
    pub kind: String,
    pub value: String,
}

impl HoverContents {
    fn markdown(value: String) -> Self {
        HoverContents::Structured(HoverMarkupContent {
            kind: "markdown".into(),
            value,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeAction {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edit: Option<WorkspaceEdit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<Command>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<Vec<Diagnostic>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceEdit {
    #[serde(skip_serializing_if = "Option::is_none", rename = "documentChanges")]
    pub document_changes: Option<Vec<TextDocumentEdit>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TextDocumentEdit {
    pub text_document: TextDocumentIdentifier,
    pub edits: Vec<TextEdit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TextEdit {
    pub range: Range,
    pub new_text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Command {
    pub title: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "commandArguments")]
    pub command_arguments: Option<Vec<Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub range: Range,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Position {
    pub line: u32,
    pub character: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublishDiagnosticsParams {
    pub uri: String,
    pub diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i32>,
}

// --------------------------------------------------------------------------
// Debounce thread communication
// --------------------------------------------------------------------------

enum DebounceCommand {
    Schedule { uri: String, deadline: Instant },
    Stop,
}

// --------------------------------------------------------------------------
// Server configuration
// --------------------------------------------------------------------------

/// LSP server configuration options.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct LspConfig {
    /// Minimum severity: "critical", "high", "medium", "low", "info"
    pub severity_threshold: String,
    /// Scan on file save
    pub scan_on_save: bool,
    /// Debounce delay in ms for real-time scans
    pub debounce_ms: u64,
    /// Enable real-time scanning on keystroke
    pub enable_real_time: bool,
    /// Restrict to specific rule IDs. Empty = all rules.
    pub enabled_rules: Vec<String>,
}

impl LspConfig {
    #[allow(dead_code)]
    fn min_severity(&self) -> i32 {
        // LSP DiagnosticSeverity: 1=Error, 2=Warning, 3=Info, 4=Hint
        match self.severity_threshold.as_str() {
            "critical" => 1,
            "high" => 2,
            "medium" => 3,
            "low" => 4,
            _ => 3,
        }
    }
}

// --------------------------------------------------------------------------
// Document state
// --------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Document {
    #[allow(dead_code)]
    uri: String,
    content: String,
    version: i32,
}

// --------------------------------------------------------------------------
// LSP Server
// --------------------------------------------------------------------------

pub struct PyneatLspServer {
    documents: Arc<Mutex<HashMap<String, Document>>>,
    config: LspConfig,
    debounce_tx: Option<std::sync::mpsc::Sender<DebounceCommand>>,
}

impl PyneatLspServer {
    pub fn new(config: LspConfig) -> Self {
        tracing_subscriber::fmt()
            .with_env_filter("pyneat=warn")
            .init();
        tracing::info!("PyNEAT LSP server starting on stdio...");

        let (debounce_tx, debounce_rx) = mpsc::channel();
        let docs = Arc::new(Mutex::new(HashMap::new()));
        let debounce_docs = Arc::clone(&docs);

        std::thread::spawn(move || {
            let mut pending_uri: Option<String> = None;
            let mut deadline: Option<Instant> = None;

            loop {
                // Calculate how long to sleep if we have a pending deadline
                let sleep_duration = if let Some(d) = deadline {
                    if d <= Instant::now() {
                        Some(Duration::from_millis(0))
                    } else {
                        Some(d - Instant::now())
                    }
                } else {
                    None
                };

                let cmd = match sleep_duration {
                    Some(d) if d == Duration::from_millis(0) => {
                        // Deadline expired — fire immediately
                        if let Some(uri) = pending_uri.take() {
                            deadline = None;
                            Self::scan_and_publish_on_thread(&debounce_docs, &uri);
                        }
                        // Now wait for a new command (don't block loop)
                        match debounce_rx.recv_timeout(Duration::from_millis(50)) {
                            Ok(c) => c,
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                continue;
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                    Some(d) => {
                        match debounce_rx.recv_timeout(d) {
                            Ok(c) => c,
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                // Timer expired — fire
                                if let Some(uri) = pending_uri.take() {
                                    deadline = None;
                                    Self::scan_and_publish_on_thread(&debounce_docs, &uri);
                                }
                                continue;
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                    None => {
                        match debounce_rx.recv() {
                            Ok(c) => c,
                            Err(_) => break,
                        }
                    }
                };

                match cmd {
                    DebounceCommand::Schedule { uri, deadline: new_deadline } => {
                        // New keystroke — reset the deadline (overwrite, not accumulate)
                        pending_uri = Some(uri);
                        deadline = Some(new_deadline);
                    }
                    DebounceCommand::Stop => {
                        pending_uri = None;
                        deadline = None;
                    }
                }
            }
        });

        Self {
            documents: docs,
            config,
            debounce_tx: Some(debounce_tx),
        }
    }

    /// Called by the debounce thread to publish diagnostics for a URI.
    fn scan_and_publish_on_thread(docs: &Arc<Mutex<HashMap<String, Document>>>, uri: &str) {
        let (content, version) = {
            let guard = match docs.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            match guard.get(uri) {
                Some(d) => (d.content.clone(), d.version),
                None => return,
            }
        };

        let findings = Self::run_security_scan_static(&content);

        let diagnostics: Vec<Diagnostic> = findings
            .into_iter()
            .map(|f| {
                let end_offset = f.end.min(content.len());
                let start_pos = position_from_offset(&content, f.start);
                let end_pos = position_from_offset(&content, end_offset);
                Diagnostic {
                    range: Range { start: start_pos, end: end_pos },
                    severity: None,
                    code: Some(serde_json::json!(&f.rule_id)),
                    source: Some("PyNEAT".into()),
                    message: f.problem,
                }
            })
            .collect();

        let params = PublishDiagnosticsParams {
            uri: uri.into(),
            diagnostics,
            version: Some(version),
        };

        let notif = JsonRpcNotification::new(
            "textDocument/publishDiagnostics",
            serde_json::to_value(params).unwrap(),
        );

        if let Ok(json) = serde_json::to_string(&notif) {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            let _ = handle.write_all(format!("Content-Length: {}\r\n\r\n", json.len()).as_bytes());
            let _ = handle.write_all(json.as_bytes());
            let _ = handle.write_all(b"\r\n");
            let _ = handle.flush();
        }
    }

    /// Run the main event loop. Reads JSON-RPC from stdin, writes to stdout.
    pub fn run(&mut self) {
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        let mut lines = stdin.lock().lines();

        while let Some(Ok(line)) = lines.next() {
            if line.trim().is_empty() {
                continue;
            }

            // Check for Content-Length header
            if line.starts_with("Content-Length:") {
                continue;
            }

            let req: Result<JsonRpcRequest, _> = serde_json::from_str(&line);

            if let Ok(req) = req {
                if req.method.is_empty() {
                    continue;
                }

                // Method notifications are handled via the handle_notification call
                if req.id.is_null() {
                    // Notification — no response expected
                    let method = req.method.clone();
                    let params = req.params.clone();
                    drop(req);
                    self.handle_notification(&method, params);
                    continue;
                }

                let response = self.handle_request(req);

                if let Some(response) = response {
                    if let Ok(json) = serde_json::to_string(&response) {
                        let _ = stdout.write_all(format!("Content-Length: {}\r\n\r\n", json.len()).as_bytes());
                        let _ = stdout.write_all(json.as_bytes());
                        let _ = stdout.write_all(b"\r\n");
                        let _ = stdout.flush();
                    }
                }
            }
        }
    }

    fn handle_request(&self, req: JsonRpcRequest) -> Option<JsonRpcResponse> {
        match req.method.as_str() {
            "initialize" => {
                tracing::info!("PyNEAT LSP: initialize request");
                let result = InitializeResult {
                    capabilities: ServerCapabilities {
                        text_document_sync: Some(1), // Full sync
                        diagnostics: Some(serde_json::json!({
                            "interFileDependencies": false,
                            "workspaceDiagnostics": false
                        })),
                        hover_provider: Some(true),
                        code_action_provider: Some(true),
                        definition_provider: Some(true),
                    },
                    server_info: Some(ServerInfo {
                        name: "pyneat-lsp".into(),
                        version: Some(env!("CARGO_PKG_VERSION").into()),
                    }),
                };
                Some(JsonRpcResponse::ok(req.id, serde_json::to_value(result).unwrap()))
            }
            "shutdown" => {
                Some(JsonRpcResponse::ok(req.id, Value::Null))
            }
            "exit" => {
                tracing::info!("PyNEAT LSP server exiting");
                std::process::exit(0);
            }
            "textDocument/hover" => {
                return self.on_hover(req);
            }
            "textDocument/codeAction" => {
                return self.on_code_action(req);
            }
            _ => None,
        }
    }

    fn handle_notification(&mut self, method: &str, params: Value) {
        match method {
            "textDocument/didOpen" => {
                if let Ok(p) = serde_json::from_value::<DidOpenParams>(params) {
                    self.on_document_open(p);
                }
            }
            "textDocument/didChange" => {
                if let Ok(p) = serde_json::from_value::<DidChangeParams>(params) {
                    self.on_document_change(p);
                }
            }
            "textDocument/didSave" => {
                if self.config.scan_on_save {
                    if let Ok(p) = serde_json::from_value::<DidSaveParams>(params) {
                        self.scan_and_publish_diagnostics(&p.text_document.uri);
                    }
                }
            }
            "initialized" => {
                tracing::info!("PyNEAT LSP: workspace initialized");
            }
            "workspace/didChangeConfiguration" => {
                if let Ok(settings) = serde_json::from_value::<serde_json::Value>(params.clone()) {
                    if let Some(pyneat_config) = settings.get("pyneat") {
                        if let Ok(_new_config) = serde_json::from_value::<LspConfig>(pyneat_config.clone()) {
                            tracing::info!("PyNEAT LSP: config updated");
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn on_document_open(&mut self, params: DidOpenParams) {
        tracing::info!("PyNEAT LSP: opening document {}", params.text_document.uri);

        {
            let mut docs = self.documents.lock().unwrap();
            docs.insert(params.text_document.uri.clone(), Document {
                uri: params.text_document.uri.clone(),
                content: params.text_document.text,
                version: params.text_document.version,
            });
        }

        self.scan_and_publish_diagnostics(&params.text_document.uri);
    }

    fn on_document_change(&mut self, params: DidChangeParams) {
        let content = params.content_changes.into_iter()
            .map(|c| c.text)
            .collect::<String>();

        let uri = params.text_document.uri.clone();
        {
            let mut docs = self.documents.lock().unwrap();
            if let Some(doc) = docs.get_mut(&uri) {
                doc.content = content;
                doc.version = params.text_document.version;
            }
        }

        if !self.config.enable_real_time {
            return;
        }

        if self.config.debounce_ms == 0 {
            let docs = Arc::clone(&self.documents);
            Self::scan_and_publish_on_thread(&docs, &uri);
        } else {
            // Cancel any pending scan for this URI (new keystroke resets timer)
            if let Some(ref tx) = self.debounce_tx {
                let _ = tx.send(DebounceCommand::Stop);
            }
            let deadline = Instant::now() + Duration::from_millis(self.config.debounce_ms);
            if let Some(ref tx) = self.debounce_tx {
                let _ = tx.send(DebounceCommand::Schedule { uri, deadline });
            }
        }
    }

    fn scan_and_publish_diagnostics(&self, uri: &str) {
        let (content, version) = {
            let docs = self.documents.lock().unwrap();
            match docs.get(uri) {
                Some(d) => (d.content.clone(), d.version),
                None => return,
            }
        };

        let findings = Self::run_security_scan_static(&content);

        let diagnostics: Vec<Diagnostic> = findings
            .into_iter()
            .map(|f| {
                let end_offset = f.end.min(content.len());
                let start_pos = position_from_offset(&content, f.start);
                let end_pos = position_from_offset(&content, end_offset);
                Diagnostic {
                    range: Range { start: start_pos, end: end_pos },
                    severity: None,
                    code: Some(serde_json::json!(&f.rule_id)),
                    source: Some("PyNEAT".into()),
                    message: f.problem,
                }
            })
            .collect();

        let params = PublishDiagnosticsParams {
            uri: uri.into(),
            diagnostics,
            version: Some(version),
        };

        let notif = JsonRpcNotification::new(
            "textDocument/publishDiagnostics",
            serde_json::to_value(params).unwrap(),
        );

        if let Ok(json) = serde_json::to_string(&notif) {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            let _ = handle.write_all(format!("Content-Length: {}\r\n\r\n", json.len()).as_bytes());
            let _ = handle.write_all(json.as_bytes());
            let _ = handle.write_all(b"\r\n");
            let _ = handle.flush();
        }
    }

    /// Static security scan used by the debounce thread (no access to self.config).
    fn run_security_scan_static(code: &str) -> Vec<crate::rules::base::Finding> {
        use crate::rules::security;
        use crate::rules::ast_rules;
        use crate::rules::extended_security;
        use crate::scanner::tree_sitter;

        let tree = match tree_sitter::parse(code) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        let mut rules: Vec<Box<dyn crate::rules::base::Rule>> = security::all_security_rules();
        rules.extend(ast_rules::all_ast_rules());
        rules.extend(extended_security::all_extended_security_rules());
        rules.extend(crate::rules::hackingtool_patterns::all_hackingtool_rules());

        // Default threshold: show critical (1), high (2), and medium (3)
        let min_severity = 3i32;

        let mut all = Vec::new();
        for rule in rules {
            for finding in rule.detect(&tree, code) {
                let finding_severity = match finding.severity.as_str() {
                    "critical" => 1i32,
                    "high" => 2,
                    "medium" => 3,
                    "low" => 4,
                    _ => 3,
                };
                if finding_severity <= min_severity {
                    all.push(finding);
                }
            }
        }
        all
    }

    fn on_hover(&self, req: JsonRpcRequest) -> Option<JsonRpcResponse> {
        let params: HoverParams = serde_json::from_value(req.params.clone()).ok()?;

        let (content, _) = {
            let docs = self.documents.lock().unwrap();
            match docs.get(&params.text_document.uri) {
                Some(d) => (d.content.clone(), d.version),
                None => return None,
            }
        };

        let findings = Self::run_security_scan_static(&content);

        let cursor_pos = params.position;
        let cursor_byte = offset_from_position(&content, cursor_pos.line, cursor_pos.character);

        for finding in findings {
            if finding.start <= cursor_byte && cursor_byte <= finding.end {
                let markdown = format!(
                    "**{}**  \n**Severity:** {}  \n**CWE:** {}  \n\n{}\n\n```\n{}\n```\n\n*Hover for details. Use `pyneat explain {}` for more.*",
                    finding.rule_id,
                    finding.severity,
                    finding.cwe_id.as_deref().unwrap_or("N/A"),
                    finding.problem,
                    finding.snippet.lines().take(3).collect::<Vec<_>>().join("\n"),
                    finding.rule_id,
                );

                let result = HoverResult {
                    contents: HoverContents::markdown(markdown),
                };
                return Some(JsonRpcResponse::ok(req.id, serde_json::to_value(result).unwrap()));
            }
        }

        None
    }

    fn on_code_action(&self, req: JsonRpcRequest) -> Option<JsonRpcResponse> {
        let params: CodeActionParams = serde_json::from_value(req.params.clone()).ok()?;

        let (content, _) = {
            let docs = self.documents.lock().unwrap();
            match docs.get(&params.text_document.uri) {
                Some(d) => (d.content.clone(), d.version),
                None => return None,
            }
        };

        let findings = Self::run_security_scan_static(&content);
        let mut code_actions: Vec<CodeAction> = Vec::new();

        for finding in findings {
            let start_pos = position_from_offset(&content, finding.start);
            let end_pos = position_from_offset(&content, finding.end.min(content.len()));

            if start_pos.line > params.range.end.line || end_pos.line < params.range.start.line {
                continue;
            }

            let fix_title = format!("Fix: {} - {}", finding.rule_id, finding.problem.lines().next().unwrap_or(""));
            let explain_title = format!("Explain: {}", finding.rule_id);

            let auto_fix_action = if finding.auto_fix_available {
                let fix = self.get_fix_for_finding(&finding, &content);
                if let Some(fix) = fix {
                    let edits = vec![TextEdit {
                        range: Range { start: start_pos, end: end_pos },
                        new_text: fix.replacement,
                    }];
                    Some(CodeAction {
                        title: fix_title,
                        kind: Some("quickfix".into()),
                        edit: Some(WorkspaceEdit {
                            document_changes: Some(vec![TextDocumentEdit {
                                text_document: TextDocumentIdentifier { uri: params.text_document.uri.clone() },
                                edits,
                            }]),
                        }),
                        command: None,
                        diagnostics: None,
                    })
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(action) = auto_fix_action {
                code_actions.push(action);
            }

            code_actions.push(CodeAction {
                title: explain_title.clone(),
                kind: Some("information".into()),
                edit: None,
                command: Some(Command {
                    title: explain_title,
                    command: "pyneat.explain".into(),
                    command_arguments: Some(vec![serde_json::json!({ "rule_id": finding.rule_id })]),
                }),
                diagnostics: None,
            });
        }

        if code_actions.is_empty() {
            None
        } else {
            Some(JsonRpcResponse::ok(req.id, serde_json::to_value(code_actions).unwrap()))
        }
    }

    fn get_fix_for_finding(&self, finding: &crate::rules::base::Finding, code: &str) -> Option<crate::rules::base::Fix> {
        use crate::rules::security;
        use crate::rules::ast_rules;
        use crate::rules::extended_security;

        let _all_rule_ids = {
            let mut ids: Vec<String> = security::all_security_rules()
                .iter().map(|r| r.id().to_string()).collect();
            ids.extend(ast_rules::all_ast_rules().iter().map(|r| r.id().to_string()));
            ids.extend(extended_security::all_extended_security_rules().iter().map(|r| r.id().to_string()));
            ids.extend(crate::rules::hackingtool_patterns::all_hackingtool_rules().iter().map(|r| r.id().to_string()));
            ids
        };

        for rule in security::all_security_rules() {
            if rule.id() == finding.rule_id {
                if finding.auto_fix_available {
                    return rule.fix(finding, code);
                }
            }
        }
        for rule in crate::rules::hackingtool_patterns::all_hackingtool_rules() {
            if rule.id() == finding.rule_id {
                if finding.auto_fix_available {
                    return rule.fix(finding, code);
                }
            }
        }
        None
    }
}

// --------------------------------------------------------------------------
// Utilities
// --------------------------------------------------------------------------

fn position_from_offset(content: &str, byte_offset: usize) -> Position {
    let mut line = 0u32;
    let mut col = 0u32;
    let mut pos = 0usize;

    for (i, c) in content.char_indices() {
        if pos >= byte_offset {
            break;
        }
        if c == '\n' {
            line += 1;
            col = 0;
        } else {
            col += 1;
        }
        pos = i + c.len_utf8();
    }

    Position { line, character: col }
}

fn offset_from_position(content: &str, line: u32, character: u32) -> usize {
    let mut current_line = 0u32;
    let byte_offset = 0usize;

    for (i, c) in content.char_indices() {
        if current_line == line && c == '\n' {
            return (byte_offset + character as usize).min(content.len());
        }
        if current_line == line && (i - byte_offset) as u32 >= character {
            return byte_offset.min(content.len());
        }
        if c == '\n' {
            current_line += 1;
        }
        if current_line > line {
            break;
        }
    }

    if current_line == line {
        (byte_offset + character as usize).min(content.len())
    } else {
        content.len()
    }
}

// --------------------------------------------------------------------------
// Public entry point
// --------------------------------------------------------------------------

/// Run the PyNEAT LSP server. Call this when `--lsp` flag is passed.
pub fn run_server() {
    let config = LspConfig::default();
    let mut server = PyneatLspServer::new(config);
    server.run();
}
