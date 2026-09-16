"""Exercise an 8 MiB synthetic volume; no CLI, credentials or host network."""
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness.storage_guard import namespace, seal, TEST_STORAGE_BYTES, STORAGE_CHECK
from harness.resource_guard import limited_execute
from backend.app.runners.process import RunnerError

CHECK = '''
import errno,json,os,pathlib
home=os.environ['HOME']
folders=[home,'/work','/tmp']
report={'shared_volume':len({os.stat(p).st_dev for p in folders})==1,
        'volume_bytes':os.statvfs('/tmp').f_blocks*os.statvfs('/tmp').f_frsize}
denied=[]
for p in ['/outside-volume-canary','/dev/shm/union-storage-canary']:
    try:
        pathlib.Path(p).write_text('FAKE')
        denied.append(False)
    except OSError as exc:
        denied.append(exc.errno==errno.EROFS)
report['outside_volume_read_only']=all(denied)
written=0
exhausted=False
for i in range(12):
    try:
        with open(folders[i%3]+'/quota-'+str(i),'wb',buffering=0) as output:
            written+=output.write(b'x'*(1024*1024))
    except OSError as exc:
        exhausted=exc.errno==errno.ENOSPC
        break
report.update(bytes_written=written,enospc=exhausted)
print(json.dumps(report))
'''


async def probe():
    report = {'scope': 'Offline synthetic storage quota', 'model_calls': 0,
              'existing_credentials_mounted': False}
    try:
        with tempfile.TemporaryDirectory(prefix='union-storage-') as tmp:
            root = Path(tmp)
            for folder in ('home', 'work', 'etc'):
                (root / folder).mkdir()
            raw = await limited_execute(namespace(root, os.environ['HOME'], storage_bytes=TEST_STORAGE_BYTES)
                                        + seal() + ['/usr/bin/python3', '-I', '-c', CHECK], '', timeout=12)
            data = json.loads(raw)
            data['host_fixture_unchanged'] = all(
                not list((root / folder).iterdir()) for folder in ('home', 'work'))
            verified = await limited_execute(namespace(root, os.environ['HOME']) + seal() +
                ['/usr/bin/python3', '-I', '-c', STORAGE_CHECK + '\nprint("VERIFIED")'], '', timeout=12)
            data['live_layout_verified'] = verified.strip() == b'VERIFIED'
            data['wrong_limit_rejected'] = False
            try:
                await limited_execute(namespace(root, os.environ['HOME'], storage_bytes=TEST_STORAGE_BYTES)
                    + seal() + ['/usr/bin/python3', '-I', '-c', STORAGE_CHECK], '', timeout=12)
            except RunnerError as exc:
                data['wrong_limit_rejected'] = exc.code == 'cli_failed'
            ok = (data.get('shared_volume') is True and data.get('volume_bytes') == TEST_STORAGE_BYTES
                  and data.get('outside_volume_read_only') is True and data.get('enospc') is True
                  and data.get('bytes_written') == TEST_STORAGE_BYTES and data['host_fixture_unchanged']
                  and data['live_layout_verified'] and data['wrong_limit_rejected'])
            report.update(status='PASS' if ok else 'BLOCKED', **data)
    except (OSError, ValueError, RunnerError):
        report.update(status='BLOCKED', error='storage_probe_failed')
    return report


if __name__ == '__main__':
    result = asyncio.run(probe())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result.get('status') == 'PASS' else 2)
