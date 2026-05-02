//! Data Flow Graph (DFG) for taint analysis.
//!
//! The DFG represents how values flow through expressions within a single function.
//! Each node represents an expression (variable, call, operation, etc.) and edges
//! represent taint propagation.

use std::collections::{HashMap, HashSet};
use crate::scanner::taint::labels::TaintLabel;

/// Unique identifier for a DFG node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DfgNodeId(pub usize);

/// The kind of expression a DFG node represents.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DfgNodeKind {
    /// A literal constant (always safe)
    Constant,
    /// A variable read
    Variable(String),
    /// An attribute/property access (e.g., obj.field)
    FieldAccess { base: DfgNodeId, field: String },
    /// An index access (e.g., arr[i])
    IndexAccess { base: DfgNodeId, index: DfgNodeId },
    /// A function/method call
    Call { callee: String, args: Vec<DfgNodeId> },
    /// A binary/unary operation
    Operation { op: String, operands: Vec<DfgNodeId> },
    /// An assignment result (the RHS expression)
    Assignment { target: String, rhs: DfgNodeId },
    /// A function parameter (treated as potentially tainted until proven otherwise)
    Parameter(String),
    /// Unknown/unresolved expression
    Unknown,
}

/// A node in the data flow graph.
#[derive(Debug, Clone)]
pub struct DfgNode {
    /// Unique node ID
    pub id: DfgNodeId,
    /// The kind of expression
    pub kind: DfgNodeKind,
    /// Source location
    pub line: usize,
    /// Column
    pub column: usize,
    /// Byte offset in source
    pub start_byte: usize,
    pub end_byte: usize,
    /// Taint labels currently applied
    pub taint: HashSet<TaintLabel>,
    /// Whether this node has been sanitized
    pub sanitized: bool,
}

impl DfgNode {
    pub fn new(id: DfgNodeId, kind: DfgNodeKind, line: usize) -> Self {
        Self {
            id,
            kind,
            line,
            column: 0,
            start_byte: 0,
            end_byte: 0,
            taint: HashSet::new(),
            sanitized: false,
        }
    }

    /// Mark this node as tainted with the given label.
    pub fn taint(&mut self, label: TaintLabel) {
        self.taint.insert(label);
    }

    /// Check if this node has any taint.
    pub fn is_tainted(&self) -> bool {
        !self.taint.is_empty() && !self.sanitized
    }

    /// Check if this node has a specific taint label.
    pub fn has_label(&self, label: &TaintLabel) -> bool {
        self.taint.contains(label)
    }

    /// Get the human-readable name for display.
    pub fn display_name(&self) -> String {
        match &self.kind {
            DfgNodeKind::Constant => "constant".to_string(),
            DfgNodeKind::Variable(name) => name.clone(),
            DfgNodeKind::FieldAccess { field, .. } => field.clone(),
            DfgNodeKind::IndexAccess { .. } => "[...]".to_string(),
            DfgNodeKind::Call { callee, .. } => format!("{}(...)", callee),
            DfgNodeKind::Operation { op, .. } => op.clone(),
            DfgNodeKind::Assignment { target, .. } => format!("{} = ...", target),
            DfgNodeKind::Parameter(name) => format!("param:{}", name),
            DfgNodeKind::Unknown => "?".to_string(),
        }
    }
}

/// A data flow graph for a single function.
#[derive(Debug, Clone)]
pub struct DataFlowGraph {
    nodes: Vec<DfgNode>,
    /// Forward edges: source -> targets (taint flows from source to targets)
    edges: HashMap<DfgNodeId, Vec<DfgNodeId>>,
    /// Reverse edges for reverse traversal
    rev_edges: HashMap<DfgNodeId, Vec<DfgNodeId>>,
}

impl Default for DataFlowGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl DataFlowGraph {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: HashMap::new(),
            rev_edges: HashMap::new(),
        }
    }

    /// Add a node and return its ID.
    pub fn add_node(&mut self, kind: DfgNodeKind, line: usize) -> DfgNodeId {
        let id = DfgNodeId(self.nodes.len());
        self.nodes.push(DfgNode::new(id, kind, line));
        id
    }

    /// Add a node with full metadata.
    pub fn add_node_full(
        &mut self,
        kind: DfgNodeKind,
        line: usize,
        column: usize,
        start_byte: usize,
        end_byte: usize,
    ) -> DfgNodeId {
        let id = DfgNodeId(self.nodes.len());
        let mut node = DfgNode::new(id, kind, line);
        node.column = column;
        node.start_byte = start_byte;
        node.end_byte = end_byte;
        self.nodes.push(node);
        id
    }

    /// Add a directed edge (taint flows from source to target).
    pub fn add_edge(&mut self, source: DfgNodeId, target: DfgNodeId) {
        self.edges.entry(source).or_default().push(target);
        self.rev_edges.entry(target).or_default().push(source);
    }

    /// Get successors of a node (forward traversal).
    pub fn successors(&self, node: DfgNodeId) -> Vec<DfgNodeId> {
        self.edges.get(&node).cloned().unwrap_or_default()
    }

    /// Get predecessors of a node (reverse traversal).
    pub fn predecessors(&self, node: DfgNodeId) -> Vec<DfgNodeId> {
        self.rev_edges.get(&node).cloned().unwrap_or_default()
    }

    /// Get a mutable reference to a node.
    pub fn node_mut(&mut self, id: DfgNodeId) -> Option<&mut DfgNode> {
        self.nodes.get_mut(id.0)
    }

    /// Get a reference to a node.
    pub fn node(&self, id: DfgNodeId) -> Option<&DfgNode> {
        self.nodes.get(id.0)
    }

    /// Iterate over all nodes with their IDs.
    pub fn nodes_with_id(&self) -> impl Iterator<Item = (DfgNodeId, &DfgNode)> {
        self.nodes.iter().enumerate().map(|(i, n)| (DfgNodeId(i), n))
    }

    /// Iterate over all nodes mutably with their IDs.
    pub fn nodes_with_id_mut(&mut self) -> impl Iterator<Item = (DfgNodeId, &mut DfgNode)> {
        self.nodes.iter_mut().enumerate().map(|(i, n)| (DfgNodeId(i), n))
    }

    /// Get all node IDs as a slice.
    pub fn node_ids(&self) -> Vec<DfgNodeId> {
        (0..self.nodes.len()).map(DfgNodeId).collect()
    }

    /// Number of nodes in the graph.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Check if the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dfg_basic() {
        let mut dfg = DataFlowGraph::new();
        let c = dfg.add_node(DfgNodeKind::Constant, 1);
        let v = dfg.add_node(DfgNodeKind::Variable("x".into()), 2);
        let call = dfg.add_node(DfgNodeKind::Call { callee: "exec".into(), args: vec![] }, 3);

        dfg.add_edge(v, call);
        dfg.add_edge(c, v);

        assert_eq!(dfg.successors(c), &[v]);
        assert_eq!(dfg.successors(v), &[call]);
        assert_eq!(dfg.predecessors(call), &[v]);
    }
}
