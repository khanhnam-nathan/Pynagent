"""Conservative rules — opt-in via flags.

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

These rules may make changes but are generally safe.
Enable with specific flags: --enable-unused, --enable-fstring, etc.
"""

from Pynagent.rules.unused import UnusedImportRule
from Pynagent.rules.init_protection import InitFileProtectionRule
from Pynagent.rules.fstring import FStringRule
from Pynagent.rules.dataclass import DataclassSuggestionRule
from Pynagent.rules.magic_numbers import MagicNumberRule

__all__ = [
    'UnusedImportRule',
    'InitFileProtectionRule',
    'FStringRule',
    'DataclassSuggestionRule',
    'MagicNumberRule',
]
