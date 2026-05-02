# ============================================================================
# Chaos Test 3: Maximum file size with repeated patterns
# Tests: Parser memory handling and performance
# ============================================================================

# Generate a large file with repeated patterns to stress test parsing
code_block = """
def func_{n}(x):
    '''Docstring for function {n}'''
    result = x * {n}
    # TODO: optimize this later
    if result > 100:
        return result / 2
    else:
        return result * 2

class Class_{n}:
    '''Class number {n}'''
    
    def __init__(self):
        self.value = {n}
    
    def method_a(self):
        return self.value + 1
    
    def method_b(self):
        return self.value - 1
"""

# Generate 1000 function/class pairs
output = ""
for i in range(1000):
    output += code_block.format(n=i)

# NOTE: exec() is removed - it makes code invalid at module level
# The parsing will find the functions defined in output via string analysis


# Also add very long strings to test string parsing
very_long_string = "A" * 100000
another_long_string = """
This is a very long multiline string
that goes on for quite a while
""" + "X" * 50000 + """
and continues after
""" * 100

# Unicode edge cases
unicode_tests = {
    "emoji": "😀" * 1000,
    "chinese": "中文测试" * 500,
    "arabic": "مرحبا" * 500,
    "special": "\x00\x01\x02\x7f" * 1000,
}
