"""Review-only by default: fixed-question agy experiment, never app enablement.

Execution needs explicit acceptance of the still-unverified tool-access risk.
Preparing this harness is not authorization to run it with existing credentials.
Success demonstrates response compatibility only, not permission enforcement.
"""
import argparse
import asyncio
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.runners.agy import AgyAdapter, MODEL_IDS, preflight
from backend.app.runners.parsers import agy_stdin
from backend.app.runners.process import RunnerError
from harness.network_guard import AGY_PROFILE_HOSTS

QUESTION = 'Reply with exactly UNION_SMOKE_OK. Do not use any tools.'
SAFE_CODES = frozenset(('auth_required', 'rate_limited', 'network_unavailable',
                       'cli_failed', 'timeout', 'output_limit', 'invalid_output',
                       'provider_unavailable'))


def review():
    # No cache metadata, processes, DNS, or account access in review mode.
    return {'execution': False, 'models': dict(MODEL_IDS), 'question': QUESTION,
            'maximum_cli_invocations': 2, 'maximum_seconds_per_invocation': 85,
            'internal_model_request_count': 'not proven; bounded by runtime, not a two-request guarantee',
            'stop_on_first_failure': True, 'automatic_retry': False,
            'cache': 'one existing file, read-only; CLI uses it',
            'network_hosts': list(AGY_PROFILE_HOSTS), 'network_port': 443,
            'network_limit': 'resolved public IPv4 allowlist; shared IPs are not a content boundary',
            'tool_policy_verified': False, 'app_enabled': False,
            'approval_required': 'accept unverified tool access to the mounted authentication file'}


async def experiment():
    """Call the isolated candidate internals only from the consent-gated harness.

The production __call__ guard remains closed. No environment toggle or server
route can reach this experiment. The prompt is a fixed benign test, not a tool
restriction; existing OS isolation and candidate deny settings stay in effect.
    """
    reports = []
    for model in MODEL_IDS:
        try:
            async with asyncio.timeout(85):
                if await asyncio.to_thread(preflight) is not True:
                    raise RunnerError('provider_unavailable')
                answer = await AgyAdapter(model)._run(agy_stdin(QUESTION).decode('utf-8'))
            matched = answer.strip() == 'UNION_SMOKE_OK'
            reports.append({'model': model, 'status': 'response_received',
                            'fixed_marker_match': matched})
            if not matched:
                break
        except (RunnerError, TimeoutError, OSError, ValueError) as exc:
            code = 'timeout' if isinstance(exc, TimeoutError) else (
                exc.code if isinstance(exc, RunnerError) and exc.code in SAFE_CODES else 'probe_failed')
            reports.append({'model': model, 'status': 'stopped', 'code': code})
            break
    return {'reports': reports, 'tool_policy_verified': False, 'app_enabled': False,
            'response_compatibility_passed': len(reports) == 2 and
                all(item.get('fixed_marker_match') is True for item in reports)}


def main(args=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--accept-unverified-tool-access', action='store_true')
    options = parser.parse_args(args)
    if not options.execute:
        print(json.dumps(review(), indent=2))
        return 0
    if not options.accept_unverified_tool_access:
        print(json.dumps({'execution': False, 'error': 'explicit_risk_acceptance_required'}))
        return 2
    print(json.dumps(asyncio.run(experiment()), indent=2))
    # Even matching responses cannot turn the outstanding security gate green.
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
