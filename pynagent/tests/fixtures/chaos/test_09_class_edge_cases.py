# ============================================================================
# Chaos Test 9: Class and inheritance edge cases
# Tests: Parser handling of complex class hierarchies
# ============================================================================

# Multiple inheritance
class Base1:
    def method(self): return 1

class Base2:
    def method(self): return 2

class Multi(Base1, Base2):
    def method(self): return 3

# Diamond inheritance
class A:
    def greet(self): return "A"

class B(A):
    pass

class C(A):
    pass

class D(B, C):
    pass

# Method Resolution Order check
assert D().greet() == "A"

# Metaclass edge case
class Meta(type):
    def __new__(mcs, name, bases, namespace, **kwargs):
        return super().__new__(mcs, name, bases, namespace)

class WithMeta(metaclass=Meta):
    pass

# Abstract class with multiple ABCs
from abc import ABC, abstractmethod, ABCMeta

class AbstractBase(ABC):
    @abstractmethod
    def must_implement(self): pass
    
    def can_implement(self): return "default"

# Protocol class (structural subtyping)
from typing import Protocol

class Readable(Protocol):
    def read(self) -> bytes: ...

# Generic base class
from typing import Generic, TypeVar

T = TypeVar('T')

class GenericBase(Generic[T]):
    def __init__(self, value: T):
        self.value = value

# Nested classes
class Outer:
    class Inner:
        class DeepInner:
            pass

# Class decorators
def add_method(cls):
    cls.new_method = lambda self: "added"
    return cls

@add_method
class Decorated:
    pass

# __slots__ edge cases
class WithSlots:
    __slots__ = ['x', 'y', '__dict__']  # Can have __dict__ + slots
    
    def __init__(self, x, y):
        self.x = x
        self.y = y

# Data class edge cases
from dataclasses import dataclass, field

@dataclass
class DataClass:
    x: int
    y: int = field(default=10)
    z: list = field(default_factory=list)

# Named tuple variations
from collections import namedtuple

Point = namedtuple('Point', ['x', 'y'])
Point3D = namedtuple('Point3D', 'x y z')  # Space-separated names

# Enum edge cases
from enum import Enum, auto, IntEnum, Flag

class Color(Enum):
    RED = 1
    GREEN = 2
    BLUE = auto()  # Auto-generated value

class Permissions(Flag):
    READ = 1
    WRITE = 2
    EXECUTE = 4

# Exception classes
class MyException(Exception):
    pass

class ChainedException(Exception):
    def __init__(self, message, cause=None):
        super().__init__(message)
        self.__cause__ = cause
