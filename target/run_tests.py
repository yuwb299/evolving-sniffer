#!/usr/bin/env python3
"""
Test runner for all protocol analyzer modules.
Run with: python3 run_tests.py
"""

import sys
import pytest

if __name__ == "__main__":
    # Run all tests in the target directory
    sys.exit(pytest.main([
        "-v",
        "--tb=short",
        "target/"
    ]))