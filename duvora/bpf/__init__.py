# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

"""Native eBPF for the Duvora agent: compiled objects in obj/, loaded through the system libbpf."""
from pathlib import Path

OBJ_DIR = Path(__file__).resolve().parent / "obj"
