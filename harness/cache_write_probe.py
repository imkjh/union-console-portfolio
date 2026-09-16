"""Verify single-file write exposure using disposable fake files only."""
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness.agy_settings_probe import cache_binding
from harness.storage_guard import namespace, seal, STORAGE_CHECK
from harness.resource_guard import limited_execute

CHECK = '''
import errno,json,os,pathlib,resource
target=pathlib.Path('/runtime/home/.gemini/antigravity-cli/antigravity-oauth-token')
report={}
resource.setrlimit(resource.RLIMIT_FSIZE,(1024*1024,1024*1024))
target.write_text('UPDATED_FAKE')
report['single_file_writable']=target.read_text()=='UPDATED_FAKE'
report['host_sibling_hidden']=not (target.parent/'host-sibling').exists()
try:
    (target.parent/'settings.json').write_text('UNEXPECTED')
    report['settings_read_only']=False
except OSError as exc:
    report['settings_read_only']=exc.errno==errno.EROFS
(target.parent/'temporary-sibling').write_text('VOLATILE_ONLY')
try:
    replacement=target.parent/'replacement'
    replacement.write_text('FAKE')
    replacement.replace(target)
    report['file_replacement_denied']=False
except OSError as exc:
    report['file_replacement_denied']=exc.errno in (errno.EBUSY,errno.EROFS)
try:
    with target.open('r+b') as f:
        f.seek(1024*1024)
        f.write(b'x')
    report['file_size_capped']=False
except OSError as exc:
    report['file_size_capped']=exc.errno==errno.EFBIG
print(json.dumps(report))
'''


async def probe():
    with tempfile.TemporaryDirectory(prefix='union-single-write-') as tmp:
        root = Path(tmp)
        for folder in ('home', 'work', 'etc', 'host-cache'):
            (root / folder).mkdir()
        host = root / 'host-cache'
        cache = host / 'fake-cache'
        cache.write_text('FAKE')
        cache.chmod(0o600)
        (host / 'host-sibling').write_text('FAKE_PRIVATE_SIBLING')
        settings = root / 'home/.gemini/antigravity-cli/settings.json'
        settings.parent.mkdir(parents=True)
        settings.write_text('FAKE_SETTINGS')
        command = (namespace(root, os.environ['HOME']) + cache_binding(cache, writable=True)
                   + seal() + ['/usr/bin/python3', '-I', '-c', STORAGE_CHECK + CHECK])
        result = json.loads(await limited_execute(command, '', timeout=12))
        result['host_sibling_unchanged'] = (host / 'host-sibling').read_text() == 'FAKE_PRIVATE_SIBLING'
        result['host_directory_unchanged'] = sorted(p.name for p in host.iterdir()) == ['fake-cache', 'host-sibling']
        result['host_settings_unchanged'] = settings.read_text() == 'FAKE_SETTINGS'
        return {'status': 'PASS' if all(v is True for v in result.values()) else 'BLOCKED',
                'existing_credentials_mounted': False, 'external_network': False, 'model_calls': 0,
                'checks': result}


if __name__ == '__main__':
    result = asyncio.run(probe())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'PASS' else 2)
