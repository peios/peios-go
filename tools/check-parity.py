#!/usr/bin/env python3
"""Fail if the reviewed public C inventory or mapped Go declarations drift."""
import hashlib
import json
import pathlib
import re

sdk = pathlib.Path(__file__).resolve().parents[1]
headers = sdk.parent / 'libpeios/include/peios'
record = json.loads((sdk / 'conformance/parity.json').read_text())
actual = {}
for path in sorted(headers.glob('*.h')):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest == record['headers_sha256'].get(path.name), f'Review changed public header: {path.name}'
    source = re.sub(r'/\*.*?\*/', '', path.read_text(), flags=re.S)
    names = re.findall(r'\b(peios_\w+)\s*\([^;{}]*\)\s*;', source, re.S)
    names += re.findall(r'extern const struct \w+ (peios_\w+)\s*;', source)
    actual.update((name, path.name) for name in names)
assert set(actual) == set(record['symbols']), f'Unmapped/stale symbols: {set(actual) ^ set(record["symbols"])}'
assert set(record['headers_sha256']) == {p.name for p in headers.glob('*.h')}
packages = {}
for path in sdk.glob('*/*.go'):
    if path.name.endswith('_test.go'):
        continue
    package = path.parent.name
    declarations = packages.setdefault(package, set())
    text = path.read_text()
    declarations.update(re.findall(r'\b(?:func|type) ([A-Z]\w*)', text))
    for recv, name in re.findall(r'func \(\w+ \*?(\w+)\) ([A-Z]\w*)', text):
        declarations.add(recv + '.' + name)
for symbol, entry in record['symbols'].items():
    assert entry['header'] == actual[symbol]
    package, target = entry['go'].split('.', 1)
    assert target in packages.get(package, set()), f'{symbol}: missing Go declaration {entry["go"]}'
    assert entry['note'].strip(), f'{symbol}: missing contract explanation'
print(f'Public capability inventory: {len(actual)} symbols across {len(record["headers_sha256"])} headers, no unmapped declarations')
