# ============================================================================
# Chaos Test 7: Edge cases in function definitions
# Tests: Parser handling of unusual function signatures
# ============================================================================

# *args and **kwargs extremes
def func_args(*args, **kwargs):
    return len(args) + len(kwargs)

func_args(1, 2, 3, a=1, b=2, c=3)  # Valid call

# Keyword-only arguments
def func_kwonly(a, *, b, c, **kwargs):
    return a + b + c

# Nested function with closure
def outer():
    x = 1
    def middle():
        y = 2
        def inner():
            # This creates a closure over both x and y
            return x + y + 1
        return inner
    return middle

# Callable class (decorator-like)
class CallableClass:
    def __call__(self):
        return "called"

callable = CallableClass()
callable()  # Invokes __call__

# Function with type annotations everywhere
from typing import List, Dict, Optional, Union, Callable, TypeVar

T = TypeVar('T')
U = TypeVar('U')

def heavily_annotated(
    x: List[int],
    y: Dict[str, Union[int, str]],
    z: Optional[Callable[[int, str], bool]],
    *args: T,
    **kwargs: U
) -> Dict[str, List[T]]:
    pass

# Decorator stacking
@decorator1
@decorator2(arg="value")
@decorator3
def decorated():
    pass

def decorator1(func): return func
def decorator2(**kw): return decorator1
def decorator3(func): return func

# Property with setter/deleter
class Prop:
    @property
    def x(self): return self._x
    
    @x.setter
    def x(self, value): self._x = value
    
    @x.deleter
    def x(self): del self._x

# Static and class methods
class StaticClass:
    @staticmethod
    def static_method(): pass
    
    @classmethod
    def class_method(cls): pass

# Context manager edge case
from contextlib import contextmanager

@contextmanager
def my_context():
    try:
        yield 1
    finally:
        pass
