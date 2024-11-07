#!/usr/bin/env python3
"""A module for filtering logs.
"""
import re

def filter_datum(fields, redaction, message, separator):
    pattern = f"({'|'.join(fields)})=.*?{separator}"
    return re.sub(pattern, lambda x: f"{x.group(1)}={redaction}{separator}", message)

