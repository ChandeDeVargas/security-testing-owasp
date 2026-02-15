"""
Pytest configuration file
Fixes Unicode encoding issues on Windows
"""
import sys
import io

# Fix Unicode encoding for Windows terminal
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer,
        encoding='utf-8',
        errors='replace'
    )
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer,
        encoding='utf-8',
        errors='replace'
    )