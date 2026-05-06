"""Universal rules — work on all languages.

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

These rules use LN-AST from the Rust parser, making them
truly cross-language without any language-specific branching.

Available rules:
    - UniversalRule: Base class for universal rules
    - HardcodedSecretsRule: Detect hardcoded passwords/API keys [PRO]
    - DebugArtifactsRule: Detect debug print/log statements
    - EmptyCatchRule: Detect empty except/catch blocks
    - TodoCommentRule: Detect TODO/FIXME comments
    - ArrowAntiPatternRule: Detect deeply nested if/else chains
"""

import warnings
from Pynagent.rules.universal.base import UniversalRule
from Pynagent.rules.universal.debug_artifacts import DebugArtifactsRule
from Pynagent.rules.universal.empty_catch import EmptyCatchRule
from Pynagent.rules.universal.todos import TodoCommentRule
from Pynagent.rules.universal.arrow_antipattern import ArrowAntiPatternRule


def _lazy_hardcoded_secrets():
    """Lazy load HardcodedSecretsRule from Pynagent-pro-engine."""
    warnings.warn(
        "HardcodedSecretsRule has been moved to Pynagent-pro-engine package. "
        "Install Pynagent-pro-engine for this feature.",
        DeprecationWarning,
        stacklevel=2
    )
    try:
        from Pynagent_pro_engine.rules import HardcodedSecretsRule
        return HardcodedSecretsRule
    except ImportError:
        raise ImportError(
            "HardcodedSecretsRule requires 'Pynagent-pro-engine' package. "
            "For commercial licensing: khanhnam.copywriting@gmail.com"
        )


def __getattr__(name):
    if name == "HardcodedSecretsRule":
        return _lazy_hardcoded_secrets()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "UniversalRule",
    "HardcodedSecretsRule",
    "DebugArtifactsRule",
    "EmptyCatchRule",
    "TodoCommentRule",
    "ArrowAntiPatternRule",
]
