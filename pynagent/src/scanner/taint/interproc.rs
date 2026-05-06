//! Inter-procedural analysis for taint tracking.
//!
//! Builds a call graph across functions and files, then uses function summaries
//! to track taint propagation across function boundaries.

#[allow(dead_code)]

use std::collections::{HashMap, HashSet};

use crate::scanner::ln_ast::LnAst;
use crate::scanner::taint::engine::{TaintConfig, TaintEngine, TaintFinding};
use crate::scanner::taint::labels::TaintLabel;

/// A function key for the call graph (name + arity for disambiguation).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionKey {
    pub name: String,
    pub arity: usize,
}

impl FunctionKey {
    pub fn new(name: &str, arity: usize) -> Self {
        Self {
            name: name.to_string(),
            arity,
        }
    }
}

/// Summary of what taint flows through a function.
#[derive(Debug, Clone, Default)]
pub struct FunctionSummary {
    pub name: String,
    /// Parameter indices that flow through to the return value (passthrough)
    pub passthrough_params: Vec<usize>,
    /// Parameter indices that propagate taint
    pub taint_params: Vec<usize>,
    /// Whether the function always returns tainted data
    pub returns_tainted: bool,
    /// Whether the function has side effects (writes to globals, files, etc.)
    pub has_side_effects: bool,
    /// Known safe (sanitized) parameters
    pub safe_params: Vec<usize>,
    /// Functions this function calls
    pub calls: Vec<FunctionKey>,
}

impl FunctionSummary {
    pub fn is_param_safe(&self, index: usize) -> bool {
        self.safe_params.contains(&index)
    }

    pub fn is_param_tainted(&self, index: usize) -> bool {
        self.taint_params.contains(&index)
    }

    pub fn is_passthrough(&self, index: usize) -> bool {
        self.passthrough_params.contains(&index)
    }
}

/// A call site in the call graph.
#[derive(Debug, Clone)]
pub struct CallSite {
    pub callee_key: FunctionKey,
    pub line: usize,
    pub arguments: Vec<String>,
    pub return_var: Option<String>,
}

/// A node in the call graph (a function definition).
#[derive(Debug, Clone)]
pub struct FunctionNode {
    pub key: FunctionKey,
    pub ast: LnAst,
    pub params: Vec<String>,
    pub calls: Vec<CallSite>,
    pub summary: Option<FunctionSummary>,
}

impl FunctionNode {
    pub fn is_leaf(&self) -> bool {
        self.calls.is_empty()
    }
}

/// Call graph for inter-procedural analysis.
#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    nodes: HashMap<FunctionKey, FunctionNode>,
    callers: HashMap<FunctionKey, Vec<FunctionKey>>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_function(&mut self, node: FunctionNode) {
        self.nodes.insert(node.key.clone(), node);
    }

    pub fn add_call(&mut self, caller: FunctionKey, callee: FunctionKey) {
        self.callers.entry(caller).or_default().push(callee);
    }

    pub fn get(&self, key: &FunctionKey) -> Option<&FunctionNode> {
        self.nodes.get(key)
    }

    pub fn get_mut(&mut self, key: &FunctionKey) -> Option<&mut FunctionNode> {
        self.nodes.get_mut(key)
    }

    pub fn get_callees(&self, caller: &FunctionKey) -> Vec<&FunctionNode> {
        self.callers
            .get(caller)
            .map(|keys| keys.iter().filter_map(|k| self.nodes.get(k)).collect())
            .unwrap_or_default()
    }

    pub fn get_callers(&self, callee: &FunctionKey) -> Vec<&FunctionNode> {
        self.callers
            .iter()
            .filter(|(_, callees)| callees.contains(callee))
            .map(|(k, _)| self.nodes.get(k))
            .filter_map(|n| n)
            .collect()
    }

    pub fn functions(&self) -> impl Iterator<Item = (&FunctionKey, &FunctionNode)> {
        self.nodes.iter()
    }

    /// Topological sort: leaf functions first, callers after callees.
    /// This ensures we analyze from leaves up so summaries are available when needed.
    pub fn topological_sort(&self) -> Vec<FunctionKey> {
        let mut visited = HashSet::new();
        let mut order = Vec::new();

        fn visit(
            key: &FunctionKey,
            graph: &CallGraph,
            visited: &mut HashSet<FunctionKey>,
            order: &mut Vec<FunctionKey>,
        ) {
            if visited.contains(key) {
                return;
            }
            visited.insert(key.clone());
            for callee in graph.get_callees(key) {
                visit(&callee.key, graph, visited, order);
            }
            order.push(key.clone());
        }

        for (key, _) in &self.nodes {
            visit(key, self, &mut visited, &mut order);
        }

        order
    }

    pub fn size(&self) -> usize {
        self.nodes.len()
    }
}

/// Inter-procedural taint analyzer.
///
/// Analyzes taint flow across function boundaries using:
///
/// 1. **Call Graph** — Maps which functions call which
/// 2. **Function Summaries** — Pre-computed taint behavior of each function
/// 3. **Bottom-up analysis** — Analyze leaf functions first, propagate summaries up
pub struct InterProceduralEngine<'a> {
    code: &'a str,
    config: TaintConfig,
    call_graph: CallGraph,
    summaries: HashMap<FunctionKey, FunctionSummary>,
    findings: Vec<TaintFinding>,
    callee_to_callers: HashMap<FunctionKey, Vec<FunctionKey>>,
}

impl<'a> InterProceduralEngine<'a> {
    pub fn new(code: &'a str) -> Self {
        Self {
            code,
            config: TaintConfig::default(),
            call_graph: CallGraph::new(),
            summaries: HashMap::new(),
            findings: Vec::new(),
            callee_to_callers: HashMap::new(),
        }
    }

    pub fn with_config(code: &'a str, config: TaintConfig) -> Self {
        Self {
            code,
            config,
            call_graph: CallGraph::new(),
            summaries: HashMap::new(),
            findings: Vec::new(),
            callee_to_callers: HashMap::new(),
        }
    }

    /// Build call graph from a single file's LnAst.
    pub fn build_call_graph(&mut self, ast: &LnAst) {
        self.build_from_files(&[(String::new(), ast.clone())]);
    }

    /// Build call graph from multiple files (cross-file analysis).
    ///
    /// This registers all function definitions, then maps call sites to their
    /// enclosing function, building edges in the call graph.
    pub fn build_from_files(&mut self, files: &[(String, LnAst)]) {
        // Pass 1: Register all function definitions
        for (_, ast) in files {
            for func in &ast.functions {
                let key = FunctionKey::new(&func.name, func.params.len());
                if !self.call_graph.nodes.contains_key(&key) {
                    let node = FunctionNode {
                        key: key.clone(),
                        ast: ast.clone(),
                        params: func.params.clone(),
                        calls: Vec::new(),
                        summary: None,
                    };
                    self.call_graph.add_function(node);
                }
            }
        }

        let all_func_keys: Vec<_> = self.call_graph.nodes.keys().cloned().collect();

        // Pass 2: Map call sites and build edges
        for (_, ast) in files {
            for call in &ast.calls {
                let caller_key = self.find_enclosing_function_key(ast, call.start_line);
                let callee_key = all_func_keys
                    .iter()
                    .find(|k| k.name == call.callee)
                    .cloned();

                if let (Some(caller), Some(callee)) = (caller_key, callee_key) {
                    if caller == callee {
                        continue; // Skip recursion for now
                    }

                    let call_site = CallSite {
                        callee_key: callee.clone(),
                        line: call.start_line,
                        arguments: call.arguments.clone(),
                        return_var: None,
                    };

                    if let Some(caller_node) = self.call_graph.get_mut(&caller) {
                        caller_node.calls.push(call_site);
                    }

                    self.call_graph.add_call(caller.clone(), callee.clone());
                    self.callee_to_callers
                        .entry(callee)
                        .or_default()
                        .push(caller);
                }
            }
        }
    }

    fn find_enclosing_function_key(&self, ast: &LnAst, line: usize) -> Option<FunctionKey> {
        for func in &ast.functions {
            if line >= func.start_line && line <= func.end_line {
                return Some(FunctionKey::new(&func.name, func.params.len()));
            }
        }
        None
    }

    /// Run the full inter-procedural analysis:
    ///
    /// 1. Topological sort (leaf functions first)
    /// 2. Analyze each function with intra-procedural TaintEngine
    /// 3. Compute function summaries
    /// 4. Back-propagate taint from callees to callers
    pub fn analyze(&mut self) {
        let order = self.call_graph.topological_sort();

        for key in order {
            self.analyze_function(&key);
        }

        self.propagate_summaries_back();
    }

    fn analyze_function(&mut self, key: &FunctionKey) {
        let node = match self.call_graph.get(key) {
            Some(n) => n,
            None => return,
        };

        let rules = crate::scanner::taint::rules::all_taint_rules();
        let mut engine = TaintEngine::new(self.code).with_config(self.config.clone());
        for rule in rules {
            engine.add_rule(rule);
        }
        engine.analyze_with_ast(&node.ast);

        self.findings.extend(engine.findings().to_vec());

        let summary = self.compute_summary(key, &engine);
        self.summaries.insert(key.clone(), summary);
    }

    /// Back-propagate: when a callee taints a param or returns taint,
    /// mark the caller's corresponding arguments as tainted sources.
    fn propagate_summaries_back(&mut self) {
        let callee_to_callers: Vec<_> = self.callee_to_callers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        for (callee_key, caller_keys) in callee_to_callers {
            let callee_summary = match self.summaries.get(&callee_key) {
                Some(s) => s.clone(),
                None => continue,
            };

            for caller_key in caller_keys {
                let caller_node = match self.call_graph.get(&caller_key) {
                    Some(n) => n.clone(),
                    None => continue,
                };

                for call_site in &caller_node.calls {
                    if call_site.callee_key != callee_key {
                        continue;
                    }

                    for (arg_idx, _arg_expr) in call_site.arguments.iter().enumerate() {
                        // If callee taints this parameter, mark it in caller's summary
                        if callee_summary.is_param_tainted(arg_idx) {
                            if let Some(summary) = self.summaries.get_mut(&caller_key) {
                                if !summary.taint_params.contains(&arg_idx) {
                                    summary.taint_params.push(arg_idx);
                                }
                            }
                        }

                        // If callee passthroughs and returns tainted, mark caller too
                        if callee_summary.is_passthrough(arg_idx) && callee_summary.returns_tainted {
                            if let Some(summary) = self.summaries.get_mut(&caller_key) {
                                if !summary.passthrough_params.contains(&arg_idx) {
                                    summary.passthrough_params.push(arg_idx);
                                }
                                summary.returns_tainted = true;
                            }
                        }
                    }
                }
            }
        }
    }

    fn compute_summary(&self, key: &FunctionKey, engine: &TaintEngine) -> FunctionSummary {
        let mut summary = FunctionSummary {
            name: key.name.clone(),
            ..Default::default()
        };

        let empty_params: Vec<String> = Vec::new();
        let params: &Vec<String> = self.call_graph.get(key).map(|n| &n.params).unwrap_or(&empty_params);

        for (idx, param) in params.iter().enumerate() {
            let mut taints_param = false;
            let mut passthrough_param = false;

            for finding in engine.findings() {
                let trace_mentions_param = finding.trace.iter().any(|t| t.snippet.contains(param));
                let has_taint_label = finding.labels.iter().any(|l| {
                    matches!(
                        l,
                        TaintLabel::Tainted
                            | TaintLabel::Sql
                            | TaintLabel::Html
                            | TaintLabel::Command
                            | TaintLabel::Path
                            | TaintLabel::Network
                            | TaintLabel::UserInput
                            | TaintLabel::FileContent
                    )
                });

                if trace_mentions_param && has_taint_label {
                    taints_param = true;
                    passthrough_param = true;
                }
            }

            if taints_param {
                summary.taint_params.push(idx);
            }
            if passthrough_param {
                summary.passthrough_params.push(idx);
            }
        }

        summary.returns_tainted = engine.findings().iter()
            .any(|f| {
                f.labels.iter().any(|l| {
                    matches!(
                        l,
                        TaintLabel::Tainted
                            | TaintLabel::Sql
                            | TaintLabel::Html
                            | TaintLabel::Command
                            | TaintLabel::Path
                            | TaintLabel::Network
                            | TaintLabel::UserInput
                            | TaintLabel::FileContent
                    )
                })
            });

        if let Some(node) = self.call_graph.get(key) {
            summary.calls = node.calls.iter().map(|c| c.callee_key.clone()).collect();
        }

        summary
    }

    pub fn findings(&self) -> &[TaintFinding] {
        &self.findings
    }

    pub fn call_graph(&self) -> &CallGraph {
        &self.call_graph
    }

    pub fn get_summary(&self, key: &FunctionKey) -> Option<&FunctionSummary> {
        self.summaries.get(key)
    }

    pub fn query_param_taint(&self, func: &str, param_idx: usize) -> bool {
        let key = self.call_graph.nodes.keys()
            .find(|k| k.name == func)
            .cloned();
        key.and_then(|k| self.summaries.get(&k))
            .map(|s| s.is_param_tainted(param_idx))
            .unwrap_or(false)
    }

    pub fn function_count(&self) -> usize {
        self.call_graph.size()
    }

    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }
}
