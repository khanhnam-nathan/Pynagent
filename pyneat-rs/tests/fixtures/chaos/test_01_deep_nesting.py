# ============================================================================
# Chaos Test 1: Maximum nesting depth
# Tests: AST parser handling of deeply nested structures
# ============================================================================

# Python allows unlimited nesting - this tests tree depth limits
def level1():
    if True:
        if True:
            if True:
                if True:
                    if True:
                        if True:
                            if True:
                                if True:
                                    if True:
                                        if True:
                                            if True:
                                                if True:
                                                    if True:
                                                        if True:
                                                            if True:
                                                                if True:
                                                                    if True:
                                                                        if True:
                                                                            if True:
                                                                                if True:
                                                                                    if True:
                                                                                        if True:
                                                                                            if True:
                                                                                                if True:
                                                                                                    if True:
                                                                                                        if True:
                                                                                                            if True:
                                                                                                                if True:
                                                                                                                    if True:
                                                                                                                        if True:
                                                                                                                            if True:
                                                                                                                                if True:
                                                                                                                                    if True:
                                                                                                                                        if True:
                                                                                                                                            if True:
                                                                                                                                                if True:
                                                                                                                                                    if True:
                                                                                                                                                        if True:
                                                                                                                                                            if True:
                                                                                                                                                                if True:
                                                                                                                                                                    if True:
                                                                                                                                                                        if True:
                                                                                                                                                                            if True:
                                                                                                                                                                                if True:
                                                                                                                                                                                    pass

# Also test deeply nested comprehensions
nested_comp = [[[[[[[[[[[[[[[[[[[[[[[[[[[x]]]]]]]]]]]]]]]]]]]]]]]]]]]] for x in range(1)]
