# ============================================================================
# Chaos Test 4: Malformed syntax (partial parsing)
# Tests: Error recovery and graceful handling of invalid syntax
# ============================================================================

# These are intentionally malformed - the parser should either:
# 1. Parse what's valid and skip the rest
# 2. Not crash (resilience)

# Unclosed parentheses/brackets
x = (1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10
y = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10
z = {1: "a", 2: "b", 3: "c"

# Missing colons after def/class/if/for/while
def bad_func()
    pass

class BadClass
    pass

if True
    pass

for i in range(10)
    pass

# Trailing garbage
x = 1
___
||||
~~~

# Incomplete ternary
y = 1 if True else

# Unclosed string
z = "this string never ends

# Extra/missing indentation (syntax error)
def indent_test():
  x = 1
    y = 2
      z = 3

# Invalid escape sequences
weird_string = "\xgg\uXXXX\v\f\n\r"

# Duplicate keywords
def dup_def():
    return 1
def dup_def():
    return 2

# Invalid syntax after valid code
valid_func()
    return 1

# Missing except colon
try:
    pass
except ValueError
    pass

# Multiple statements on same line with errors
x = 1; y = 2; z = (broken
