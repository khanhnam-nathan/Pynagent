"""Rule groupings and exports.

Copyright (c) 2026 Pynagent Authors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, contact: khanhnam.copywriting@gmail.com

Available rule packages:
  - Security rules: secrets.py, security.py, iac_security.py
  - Quality rules: quality.py, refactoring.py
  - Performance rules: performance.py
  - Code cleaning rules: debug.py, comments.py, unused.py
  - AI-specific rules: ai_bugs.py, duplication.py
"""

from Pynagent.rules.base import Rule
from Pynagent.rules.imports import ImportCleaningRule
from Pynagent.rules.naming import NamingConventionRule
from Pynagent.rules.refactoring import RefactoringRule
from Pynagent.rules.security import SecurityScannerRule
from Pynagent.rules.security_registry import SECURITY_RULES_REGISTRY, get_security_rule, get_all_rule_ids
from Pynagent.rules.quality import CodeQualityRule
from Pynagent.rules.performance import PerformanceRule
from Pynagent.rules.isolated import IsolatedBlockCleaner
from Pynagent.rules.debug import DebugCleaner
from Pynagent.rules.comments import CommentCleaner
from Pynagent.rules.unused import UnusedImportRule
from Pynagent.rules.redundant import RedundantExpressionRule
from Pynagent.rules.deadcode import DeadCodeRule
from Pynagent.rules.is_not_none import IsNotNoneRule
from Pynagent.rules.magic_numbers import MagicNumberRule
from Pynagent.rules.range_len_pattern import RangeLenRule
from Pynagent.rules.typing import TypingRule
from Pynagent.rules.match_case import MatchCaseRule
from Pynagent.rules.dataclass import DataclassSuggestionRule, DataclassAdderRule
from Pynagent.rules.init_protection import InitFileProtectionRule
from Pynagent.rules.fstring import FStringRule, StringConcatRule
from Pynagent.rules.ai_bugs import AIBugRule
from Pynagent.rules.duplication import CodeDuplicationRule
from Pynagent.rules.naming import NamingInconsistencyRule

# Taint analysis and secret classification
from Pynagent.rules.secret_classifier import (
    SecretType,
    classify_secret,
    get_fix_hint,
    get_severity_for_type,
)
from Pynagent.rules.taint_analysis import (
    TaintTracker,
    TaintLevel,
    TaintSource,
    DangerousSink,
    analyze_taint,
    get_taint_report,
)

# Rule groupings for easier discovery
from Pynagent.rules import safe
from Pynagent.rules import conservative
from Pynagent.rules import destructive

# Core types for security scanning
from Pynagent.core.types import (
    SecuritySeverity,
    SecurityFinding,
    DependencyFinding,
    IgnoreEntry,
    CWE_SEVERITY_MAP,
    OWASP_SEVERITY_MAP,
)
