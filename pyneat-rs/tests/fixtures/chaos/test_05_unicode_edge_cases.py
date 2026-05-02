# ============================================================================
# Chaos Test 5: Unicode and encoding edge cases
# Tests: Proper handling of various Unicode characters
# ============================================================================

# Mixed Unicode in identifiers (Python 3 allows Unicode identifiers)
def função_ção():
    variável = "测试"
    return variável

# Unicode confusables
# These look like regular characters but are different code points
confusables = {
    "greek_ο": "ο",      # Greek omicron vs Latin 'o'
    "cyrillic_а": "а",    # Cyrillic 'a' vs Latin 'a'
    "math_ⅽ": "ⅽ",        # Roman numeral 50
    "fullwidth_a": "ａ",  # Fullwidth Latin
}

# Zero-width characters (invisible)
zero_width = "\u200b\u200c\u200d\ufeff"
hidden_in_code = f"visible{zero_width}code"

# Directional override characters
rtl_override = "\u202e" + "filename.exe"  # Right-to-left override
ltr_override = "\u202d" + "test.py"       # Left-to-right override

# Various Unicode line separators
line_sep = "Line1\u2028Line2\u2029Line3"

# Emoji in various contexts
emoji_in_strings = "👨‍👩‍👧‍👦"  # Family emoji (ZJW sequence)
emoji_in_vars = "result_📊"  # Not valid Python but tests parser
emoji_in_comments = "# 😱😈🤖💻🖥️🛠️"  # Should be fine

# Encoding declarations (PEP 263)
# -*- coding: utf-8 -*-
# coding: latin-1

# Various string formats
string_formats = {
    "bytes": b"binary \x00\xff",
    "raw": r"raw \n not a newline",
    "fstring": f"value is {42}",
    "fstring_nested": f"outer {f'inner {1+1}'}",
    "triple_quote": """
        Triple quoted
        string
    """,
    "single_quote": 'single "quotes"',
    "double_quote": "double 'quotes'",
}

# Null bytes in strings (valid in Python)
null_in_string = "hello\x00world"
