"""Scan working tree, index, and reachable Git history; never print matched values."""
import argparse
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 4 * 1024 * 1024
MEDIA = {'.png', '.jpg', '.jpeg', '.woff2'}
PATTERNS = {
    'private_key': re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'api_key': re.compile(rb'\b(?:sk-[A-Za-z0-9_-]{24,}|AIza[A-Za-z0-9_-]{30,}|gh[pousr]_[A-Za-z0-9]{25,})'),
    'jwt': re.compile(rb'eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}'),
    'credential_assignment': re.compile(rb'(?i)["\'](?:access_token|refresh_token|client_secret|api_key)["\']\s*:\s*["\'][A-Za-z0-9_/-]{16,}["\']'),
}


def scan(root):
    def git(*args, input=None):
        return subprocess.run(['git', *args], cwd=root, input=input,
                              capture_output=True, check=True).stdout

    if Path(git('rev-parse', '--show-toplevel').decode().strip()).resolve() != root.resolve():
        raise ValueError('repository_root_mismatch')
    findings, incomplete = [], []
    counts = {'working_tree': 0, 'index': 0, 'history': 0, 'excluded_media': 0}

    def excluded(name):
        if Path(name).suffix.lower() in MEDIA:
            counts['excluded_media'] += 1
            return True
        return False

    def inspect(name, data, area):
        counts[area] += 1
        for kind, pattern in PATTERNS.items():
            if pattern.search(data):
                findings.append({'path': name, 'kind': kind, 'area': area})

    paths = git('ls-files', '--cached', '--others', '--exclude-standard', '-z')
    for raw in sorted(set(filter(None, paths.split(b'\0')))):
        name = raw.decode('utf-8', errors='surrogateescape')
        path = root / name
        if path.is_symlink() or not path.is_file() or excluded(name):
            continue
        if path.stat().st_size > MAX_BYTES:
            incomplete.append({'path': name, 'kind': 'size_limit', 'area': 'working_tree'})
            continue
        inspect(name, path.read_bytes(), 'working_tree')

    def inspect_blob(oid, name, area):
        if excluded(name):
            return
        size = int(git('cat-file', '-s', oid))
        if size > MAX_BYTES:
            incomplete.append({'path': name, 'kind': 'size_limit', 'area': area})
            return
        inspect(name, git('cat-file', 'blob', oid), area)

    # Inspect every staged blob, even if worktree content differs or a merge is unresolved.
    for entry in filter(None, git('ls-files', '--stage', '-z').split(b'\0')):
        header, name = entry.split(b'\t', 1)
        _, oid, _ = header.split()
        inspect_blob(oid.decode(), name.decode('utf-8', errors='surrogateescape'), 'index')

    objects = git('rev-list', '--objects', '--all').splitlines()
    if objects:
        # rev-list deduplicates content across commits; deleted files remain reachable.
        metadata = git('cat-file', '--batch-check=%(objectname) %(objecttype)',
                       input=b'\n'.join(row.split(b' ', 1)[0] for row in objects) + b'\n')
        for row, meta in zip(objects, metadata.splitlines(), strict=True):
            oid, kind = meta.split()
            if kind == b'blob':
                parts = row.split(b' ', 1)
                name = parts[1].decode('utf-8', errors='replace') if len(parts) == 2 else '<unnamed blob>'
                inspect_blob(oid.decode(), name, 'history')

    return {'counts': counts, 'findings': findings, 'incomplete': incomplete,
            'history': 'SCANNED: reachable blobs from all refs' if objects else 'N/A: no commits',
            'scope': 'Working tree (nonignored), full index, reachable Git file blobs. '
                     'Media, reflog-only/unreachable objects, commit messages and external credential/CLI stores excluded. '
                     'Pattern scan is not proof of absence.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        report = scan(args.root.resolve())
    except (OSError, ValueError, subprocess.CalledProcessError):
        print(json.dumps({'error': 'scan_failed'}))
        return 2
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 1 if report['findings'] or report['incomplete'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
