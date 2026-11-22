# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

"""Validation helpers shared by the control-plane modules."""
import json
import math
import re


class Problem(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def name(value, field="name"):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,62}", value):
        raise Problem(f"{field} must contain 1–63 lowercase letters, digits, dots, underscores or hyphens")
    return value


def finite(value, field, low=0, high=1e15):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not low <= value <= high:
        raise Problem(f"{field} must be a finite number between {low} and {high}")
    return value
