# ============================================================================
# Chaos Test 6: Complex control flow
# Tests: Parser handling of unusual control flow patterns
# ============================================================================

# Goto-like patterns (exception-based)
def goto_pattern():
    class GoTo(Exception): pass
    class Label(Exception): pass
    
    try:
        while True:
            try:
                for i in range(10):
                    if i == 3:
                        raise GoTo()
            except GoTo:
                break
            raise Label()
    except Label:
        pass
    return "returned via goto"

# Exception in finally (Python allows this)
try:
    x = 1
finally:
    try:
        pass
    except:
        pass

# try/except/else/finally combinations
try:
    pass
except ValueError:
    pass
except TypeError:
    pass
else:
    pass
finally:
    pass

# Multiple returns in nested structures
def nested_returns():
    for i in range(10):
        for j in range(10):
            if i == 5 and j == 5:
                return (i, j)
            elif i == 0:
                continue
            elif i > 8:
                break
    else:
        return None

# Yield from with complex expressions
def complex_yield():
    yield (x for x in range(10))
    yield {x: x**2 for x in range(5)}
    yield {x for x in range(5)}
    yield from (x for x in range(10) if x % 2 == 0)
    yield from {str(x): x for x in range(3)}
    yield from {x for x in range(3)}

# Lambda with multiple expressions (illegal but tests error handling)
# lambda x: (x, x+1)  # This is actually valid

# Async/await edge cases
async def async_edge():
    await (await (await some_func()))
    async with some_ctx():
        async for item in async_gen():
            pass

# Walrus operator edge cases
def walrus_edge():
    if (n := len([1, 2, 3])) > 2:
        print(n)
    
    # Nested walrus
    if (x := (y := 1) + 1) == 2:
        assert x == 2 and y == 1
    
    # Walrus in list comprehension
    result = [y := x + 1 for x in range(5) if y > 2]
