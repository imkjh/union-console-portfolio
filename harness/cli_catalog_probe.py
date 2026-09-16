"""Metadata-only CLI probe. No prompts, credentials, raw stderr, or model usage."""
import json
import os
import subprocess
import tempfile


def main():
    env={k:os.environ[k] for k in ('HOME','LANG') if k in os.environ}
    env['PATH']='/home/your-user/.nvm/versions/node/v24.20.0/bin:/home/your-user/.local/bin:/usr/bin:/bin'
    with tempfile.TemporaryDirectory(prefix='union-catalog-') as cwd:
        for provider,argv in [
            ('agy',['/opt/union-cli/agy','--log-file','/dev/null','models']),
        ]:
            try:
                result=subprocess.run(argv,cwd=cwd,env=env,capture_output=True,timeout=25)
                output=result.stdout.decode('utf-8',errors='replace')
                print(json.dumps({'provider':provider,'exit_code':result.returncode,'listed_models':[m for m in ['gemini-3.1-pro-high','claude-sonnet-4-6'] if m in output], 'error_code':None if result.returncode==0 else 'catalog_unavailable'}))
            except (OSError,subprocess.TimeoutExpired):
                print(json.dumps({'provider':provider,'error_code':'catalog_unavailable'}))


if __name__=='__main__':main()
