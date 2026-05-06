# Pynagent - AI Code Cleaner.
#
# Copyright (C) 2026 Pynagent Authors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# For commercial licensing, contact: khanhnam.copywriting@gmail.com

"""Multi-language clean rules using LN-AST.

These rules use the Language-Neutral AST (LN-AST) produced by Pynagent-rs
(tree-sitter based parser) to transform code in JavaScript, TypeScript,
Go, Java, Rust, C#, PHP, and Ruby.

Usage:
    from Pynagent.rules.multilang import UnusedFunctionRule, UnusedImportRule

All rules in this module:
    - MultilangCleanRule       (base class)
    - UnusedFunctionRule      (unused function removal)
    - UnusedImportRule        (unused import removal)
    - RemoveTodoRule          (TODO/FIXME comment removal)
    - DeepNestingRule         (deep nesting detection)
    - EmptyCatchRule          (empty catch block handling)
    - DebugStatementRule      (debug statement removal)
    - RedundantCommentRule    (placeholder comment removal)
"""

from Pynagent.rules.multilang.base import MultilangCleanRule
from Pynagent.rules.multilang.unused_function import UnusedFunctionRule
from Pynagent.rules.multilang.unused_import import UnusedImportRule
from Pynagent.rules.multilang.remove_todos import RemoveTodoRule
from Pynagent.rules.multilang.deep_nesting import DeepNestingRule
from Pynagent.rules.multilang.empty_catch import EmptyCatchRule
from Pynagent.rules.multilang.debug_statements import DebugStatementRule
from Pynagent.rules.multilang.redundant_comments import RedundantCommentRule

__all__ = [
    "MultilangCleanRule",
    "UnusedFunctionRule",
    "UnusedImportRule",
    "RemoveTodoRule",
    "DeepNestingRule",
    "EmptyCatchRule",
    "DebugStatementRule",
    "RedundantCommentRule",
]
