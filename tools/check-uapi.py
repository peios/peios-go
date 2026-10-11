#!/usr/bin/env python3
"""Refuse drift between vendored UAPI declarations and the recorded PKM revision."""
import json, pathlib, subprocess
root=pathlib.Path(__file__).resolve().parent.parent
revision=json.loads((root/'conformance/references.json').read_text())['pkm']
for name in ['zconst.go','ztypes.go','LICENSE','LICENSE.GPL-2.0-only','LICENSE.Linux-syscall-note']:
    expected=subprocess.check_output(['git','-C',str(root.parent/'pkm'),'show',f'{revision}:uapi/generated/go/{name}'])
    if expected!=(root/'internal/uapi'/name).read_bytes():
        raise SystemExit(f'UAPI mismatch: {name}; regenerate and update references.json deliberately')
print(f'UAPI matches PKM {revision}')
