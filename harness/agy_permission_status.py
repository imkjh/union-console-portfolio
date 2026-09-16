import asyncio,json,os,sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness.agy_tool_canary import CanaryAdapter
from backend.app.runners import agy

WORKER = '''import asyncio,json,os
from process import execute,RunnerError
async def main():
 out=b''
 def failure(stdout,stderr):
  nonlocal out
  out=stdout
  return 'cli_failed'
 ok=False
 try:
  out=await execute(['/usr/bin/env','HOME='+os.environ['HOME'],'PLAYWRIGHT_DRIVER_PATH=/disabled-browser','/cli/agy','-p','/permissions','--output-format','json','--log-file','/dev/stderr'],'','/work',timeout=20,limit=131072,classify_failure=failure)
  ok=True
 except RunnerError: pass
 text=out.decode(errors='replace')
 print(json.dumps({'cli_exit_success':ok,'deny_rule_literals_present':{a: a+'(*)' in text for a in ('read_file','write_file','read_url','execute_url','command','unsandboxed','mcp')},'known_errors':[s for s in ('authentication required','unavailable','unsupported') if s in text.lower()],'has_deny_label':'deny' in text.lower(),'has_permission_label':'permission' in text.lower(),'raw_output_saved':False}))
asyncio.run(main())
'''
class Inspect(CanaryAdapter):
 async def _execute(self,root,command,message):
  (root/'inspector.py').write_text(WORKER)
  pos=command.index('--remount-ro')
  command[pos:pos]=['--ro-bind',str(root/'inspector.py'),'/probe/permission_status.py','--ro-bind',str(Path(agy.__file__).parent/'process.py'),'/probe/process.py']
  cli=next(i for i,v in enumerate(command) if v=='/cli/agy' and command[i+1:i+2]==['--input-format'])
  command[cli:]=['/usr/bin/python3','/probe/permission_status.py']
  command=agy.guarded_command(command,root,provider='agy-profile-review')
  return json.loads(await agy.limited_execute(command,'',timeout=30,limit=8192))
async def main():
 if not agy.preflight(): print(json.dumps({'error':'preflight_failed'}));return
 print(json.dumps(await Inspect('gemini')._run(''),indent=2))
if __name__ == '__main__':
 import argparse
 parser=argparse.ArgumentParser(description='Read official agy permission rule presence; review by default')
 parser.add_argument('--execute',action='store_true')
 if parser.parse_args().execute: asyncio.run(main())
 else: print(json.dumps({'execution':False,'command':'agy -p /permissions','existing_credentials':'one read-only cache','model_question':False}))
