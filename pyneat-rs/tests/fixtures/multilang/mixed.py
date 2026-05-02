# Multi-language test fixtures
# This file mixes multiple language patterns for cross-language testing
# DO NOT use as templates!

# Python patterns
import os
import subprocess

def python_vuln(user_input):
    os.system("ls " + user_input)
    eval(user_input)
    return "sk-1234567890abcdef"

# JavaScript patterns (in Python file for mixed analysis)
# function jsCmd(input) { eval(input); }
# const key = "sk_live_abcdef1234567890";

# Go patterns
# package main
# func main() { os.system(userInput) }

# TODOs and debug markers
# TODO: Fix hardcoded secret
# HACK: Temporary bypass
# FIXME: Remove before production
# DEBUG: print(user_data)

# Long function (quality issue)
def very_long_function_with_too_many_lines_of_code_that_violates_best_practices(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z):
    x = a + b + c + d + e + f + g + h + i + j + k + l + m + n + o + p + q + r + s + t + u + v + w + x + y + z
    return x

# Empty catch block
try:
    risky_operation()
except:
    pass

# Magic numbers
def calculate_total(price, quantity):
    return price * quantity * 1.08 * 0.95

# Deep nesting
if condition1:
    if condition2:
        if condition3:
            if condition4:
                if condition5:
                    risky_call()
