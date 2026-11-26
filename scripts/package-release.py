#!/usr/bin/env python3
"""Create a Linux release with correct executable modes and a SHA-256 manifest."""
import argparse
import hashlib
from pathlib import Path
import tarfile

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='dist/ssh-protecter-0.1.0-rc4-linux-amd64.tar.gz')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    files = [root / name for name in ('README.md', 'CONTEXT.md', 'go.mod', 'go.sum', 'dist/ssh-protecter-linux-amd64')]
    for folder in ('cmd', 'internal', 'configs', 'deploy', 'docs', 'scripts', 'dist/fault-tests'):
        for item in (root / folder).rglob('*'):
            if item.is_symlink():
                raise SystemExit(f'Refusing release symlink: {item}')
            if item.is_file() and '__pycache__' not in item.parts:
                files.append(item)
    required = [root / f'dist/fault-tests/{name}.test' for name in ('cli', 'state', 'service', 'timeguard', 'firewall', 'totp')]
    if any(not item.is_file() for item in files + required):
        raise SystemExit('Missing release input; build Linux program and fault-test binaries first.')
    manifest = root / 'dist/SHA256SUMS'
    manifest.write_text(''.join(f'{hashlib.sha256(item.read_bytes()).hexdigest()}  {item.relative_to(root).as_posix()}\n' for item in sorted(files)), encoding='utf-8', newline='\n')
    output = root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    def metadata(info):
        info.uid = info.gid = 0
        info.uname = info.gname = 'root'
        info.mode = 0o755 if info.name.endswith('.sh') or info.name.startswith('dist/fault-tests/') or info.name == 'dist/ssh-protecter-linux-amd64' else 0o644
        return info
    with tarfile.open(output, 'w:gz') as archive:
        for item in sorted(files + [manifest]):
            archive.add(item, arcname=item.relative_to(root).as_posix(), filter=metadata)
    checksum = output.with_name(output.name + '.sha256')
    checksum.write_text(f'{hashlib.sha256(output.read_bytes()).hexdigest()}  {output.name}\n', encoding='utf-8', newline='\n')
    print(output)
    print(checksum)

if __name__ == '__main__':
    main()
