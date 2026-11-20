# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

"""Create source archives without keys, databases, build output, or bytecode."""
import hashlib
import re
import tarfile
import zipfile
from pathlib import Path

root=Path(__file__).resolve().parents[1]
version=re.search(r'__version__\s*=\s*"([^"]+)"',(root/'duvora'/'__init__.py').read_text()).group(1)
out=root/'dist';out.mkdir(exist_ok=True)
excluded={'.git','__pycache__','.venv','dist','node_modules','test-results','build'}
def skip(rel):
    return any(x in excluded or x.endswith('.egg-info') for x in rel.parts) or rel.parts[:2]==('duvora','static')
files=[p for p in root.rglob('*') if p.is_file() and not skip(p.relative_to(root)) and p.name not in {'.env','keys.json'} and not p.name.endswith(('.pyc','.db','.db-wal','.db-shm'))]
zip_path=out/f'duvora-{version}.zip'
with zipfile.ZipFile(zip_path,'w',zipfile.ZIP_DEFLATED) as z:
    for p in sorted(files):z.write(p,Path('duvora')/p.relative_to(root))
tar_path=out/f'duvora-{version}.tar.gz'
with tarfile.open(tar_path,'w:gz') as t:
    for p in sorted(files):t.add(p,arcname=str(Path('duvora')/p.relative_to(root)))
(out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in [zip_path,tar_path]))
print(f'Packaged {len(files)} source files')
