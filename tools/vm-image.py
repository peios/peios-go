#!/usr/bin/env python3
"""Make a newc archive of the SDK probes and their reference runtime libraries."""
import gzip,pathlib,re,stat,subprocess,sys
out,refs=map(pathlib.Path,sys.argv[1:])
files={'init':out/'init','probe.test':out/'probe.test','c-oracle':refs/'c-oracle','rust-oracle':refs/'rust/debug/peios-go-rust-oracle','lib/libpeios.so.0':refs/'libpeios/release/libpeios.so'}
for exe in list(files.values()):
    result=subprocess.run(['ldd',str(exe)],text=True,capture_output=True)
    for p in re.findall(r'(?:=>\s+)?(/\S+)',result.stdout):
        if 'libpeios.so' in p:continue
        files[p.lstrip('/')]=pathlib.Path(p)
entries={}
for name,p in files.items():
    for parent in pathlib.PurePosixPath(name).parents:
        if str(parent)!='.':entries[str(parent)]=(stat.S_IFDIR|0o755,b'')
    entries[name]=(stat.S_IFREG|0o755,p.read_bytes())
for name in ['proc','sys','dev','tmp']:entries[name]=(stat.S_IFDIR|0o755,b'')
archive=bytearray()
for ino,(name,(mode,data)) in enumerate([*sorted(entries.items()),('TRAILER!!!',(0,b''))],1):
    name=name.encode()+b'\0'
    fields=[ino,mode,0,0,1,0,len(data),0,0,0,0,len(name),0]
    archive+=b'070701'+b''.join(f'{x:08x}'.encode() for x in fields)+name
    archive+=b'\0'*(-len(archive)%4);archive+=data;archive+=b'\0'*(-len(archive)%4)
(out/'initramfs.cpio.gz').write_bytes(gzip.compress(archive,mtime=0))
