# ============================================================================
# Chaos Test 8: Import and module edge cases
# Tests: Parser handling of various import patterns
# ============================================================================

# Simple imports
import os
import sys
import json

# From imports with various patterns
from collections import defaultdict, OrderedDict, namedtuple
from os.path import join, split, dirname
from typing import List as ListType, Dict as DictType

# Relative imports (edge cases)
# from . import module
# from .. import parent_module
# from .sub import sub_module

# Alias patterns
import numpy as np
import pandas as pd
from collections import Counter as C, deque as D

# __future__ imports (must be first)
from __future__ import annotations
from __future__ import division
from __future__ import print_function

# Multiple imports on one line
import time, random, hashlib, base64

# Star import (discouraged but valid)
# from os import *  # Commented out - too dangerous

# Import with complex dotted paths
import scipy.stats.exponweib as exp
from matplotlib.pyplot import scatter as plt_scatter

# Conditional imports (in function)
def conditional_import():
    try:
        import requests
    except ImportError:
        import urllib.request as requests
    return requests

# Dynamic import
def dynamic_import(module_name):
    import importlib
    return importlib.import_module(module_name)

# __import__ usage
dynamic = __import__('os')

# Module-level dunder names
__all__ = ['public_func', 'PublicClass']
__version__ = '1.0.0'
__author__ = 'Test'
__doc__ = 'Test module'

# __getattr__ for lazy imports (Python 3.7+)
# def __getattr__(name):
#     if name == 'slow_module':
#         import importlib
#         return importlib.import_module('slow_module')
#     raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

# Package-relative import patterns
# from . import submodule
# from .submodule import function
# from .. import parent
