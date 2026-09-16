"""Review pinned Ubuntu packages; --prepare extracts locally, never installs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness.network_guard import dependencies_verified

PACKAGES = {
    'slirp4netns': ('1.2.1-1build2', '3fc72a72a376a3ad3b439434bc87d89d245f9d54a1d540e8a06b74d4e2385e0a'),
    'libslirp0': ('4.7.0-1ubuntu3.1', '4efa2d1c509de4d10fe965e86a3d864bf542996caf476d9111fd882c73857164'),
    'nftables': ('1.0.9-1ubuntu0.1', 'd648859fccde3c17b8b9b89993427564f91f394a39306db1f67bd5ea3ac42c6e'),
    'libnftables1': ('1.0.9-1ubuntu0.1', 'fcaee001747a6adaa0cd9337fef437b3aa7a7a6d5246b62fbd4784d3d6a5009e'),
    'libnftnl11': ('1.2.6-2build1', 'e5bde5c9cbb95082700011f0b7ef2c0a41900b0a9fd7434f6e90448e2a7b4e50'),
}


def prepare():
    if dependencies_verified():
        return
    directory = ROOT / '.network-deps/packages'
    directory.mkdir(parents=True, exist_ok=True)
    for name, (version, digest) in PACKAGES.items():
        package = directory / f'{name}_{version}_amd64.deb'
        if not package.exists():
            subprocess.run(['/usr/bin/apt-get', 'download', f'{name}={version}'],
                           cwd=directory, check=True, timeout=60)
        if package.is_symlink() or hashlib.sha256(package.read_bytes()).hexdigest() != digest:
            raise ValueError('package_digest_mismatch')
        subprocess.run(['/usr/bin/dpkg-deb', '-x', str(package), str(directory.parent / 'root')],
                       check=True, timeout=10)
    if not dependencies_verified():
        raise ValueError('extracted_files_unverified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare', action='store_true')
    args = parser.parse_args()
    try:
        if args.prepare:
            prepare()
        print(json.dumps({'dependencies_verified': dependencies_verified(),
                          'system_install': False, 'packages': list(PACKAGES)}))
    except (OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({'error': 'network_dependencies_failed'}))
        raise SystemExit(2)
