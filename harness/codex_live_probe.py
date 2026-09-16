"""Review-only by default. Execute one GPT subscription probe only after approval.

No API key, credential parsing/copying, proxy, arbitrary prompt, or UI enablement.
The explicit --execute action needs approval for OAuth-refresh and CLI-network risks.
"""
import argparse
import asyncio
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.runners.codex import CodexAdapter, preflight
from backend.app.runners.process import RunnerError
from harness.network_guard import CODEX_HOSTS

QUESTION = '한국어로 짧게 인사해 주세요.'


def review():
    return {**preflight(),
        'mode': 'review_only', 'model': 'gpt-6-astra', 'question': QUESTION,
        'model_invocations': 0, 'live_ready': False,
        'auth_access': 'Official CLI only; one read-only file, no copy/content inspection',
        'network': {'hosts': list(CODEX_HOSTS), 'port': 443, 'private_namespace': True,
                    'dns_inside_cli': False, 'host_network_fallback': False},
        'resource_limits': '512 MiB, zero swap, 0.5 CPU, 64 tasks; total call deadline 85s',
        'storage_limits': '128 MiB shared volatile HOME/cwd/tmp',
        'tool_policy': 'Root deny; shell/MCP/plugins/hooks/browser/code-mode disabled',
        'risks': ['Subscription usage for one fixed question',
                  'Native OAuth refresh may fail to save on the read-only file and require login again',
                  'DNS-pinned public IP/port boundary; shared IPs are not an HTTP content boundary'],
        'requires_explicit_approval': True}


async def run_once(plan):
    report = {'mode': 'live_cli_probe', 'model': 'gpt-6-astra', 'model_invocations': 0, 'live_ready': False}
    if any(plan.get(key) is not True for key in
           ('tested_cli_matches', 'auth_cache_regular_file', 'network_dependencies_verified')):
        return {**report, 'error': 'preflight_blocked'}
    try:
        report['model_invocations'] = None  # Adapter can fail before model inference.
        answer = await CodexAdapter()(QUESTION)
        report.update(status='PASS', model_invocations=1, response_nonempty=True, response_characters=len(answer))
    except RunnerError as exc:
        report['error'] = exc.code
        if getattr(exc, 'stage', None) in {'isolation', 'catalog', 'auth_status', 'inference'}:
            report['stage'] = exc.stage
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', help='Run only after explicit risk approval')
    args = parser.parse_args()
    plan = review()
    report = asyncio.run(run_once(plan)) if args.execute else plan
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 2 if report.get('error') else 0


if __name__ == '__main__':
    raise SystemExit(main())
