"""Fail-closed registry. A flag cannot bypass unverified live security gates."""
import asyncio
from types import MappingProxyType
from .process import RunnerError

MODELS = {
    "gpt": {"name": "GPT", "model_id": "gpt-6-astra", "provider": "Codex CLI", "model_verified": False},
    "gemini": {"name": "Gemini", "model_id": "gemini-3.1-pro-high", "provider": "Antigravity CLI", "model_verified": False},
    "claude": {"name": "Claude", "model_id": "claude-sonnet-4-6", "provider": "Antigravity CLI", "model_verified": False},
}


class LiveRunner:
    """Register only adapters whose provider gates have been completed.

    This registry is constructed by trusted server code, never from HTTP or
    environment settings. Production registers only preflight-verified providers.
    Tests can supply synthetic adapters without enabling any production CLI.
    """
    def __init__(self, adapters=None):
        registered = dict(adapters) if adapters is not None else {}
        if any(model not in MODELS or not callable(adapter)
               for model, adapter in registered.items()):
            raise ValueError("invalid_provider_registration")
        self._adapters = MappingProxyType(registered)

    def available(self, model):
        return model in self._adapters

    async def __call__(self, model, prompt, attempt):
        adapter = self._adapters.get(model)
        if adapter is None:
            raise RunnerError("provider_unavailable")
        return await adapter(prompt)


class DemoRunner:
    """Deterministic fixtures, never used as fallback from live."""
    def __init__(self, scenario="normal"):
        self.scenario = scenario

    async def __call__(self, model, prompt, attempt):
        await asyncio.sleep({"gpt": 0.7, "gemini": 1.3, "claude": 1.9}[model])
        if self.scenario == "recovery" and attempt == 1:
            if model == "gemini":
                raise RunnerError("cli_failed")
            if model == "claude":
                raise RunnerError("timeout")
        perspectives = {
            "gpt": "핵심부터 작게 시작해 보세요.\n\n1. 해결할 문제를 한 문장으로 정리해요.\n2. 꼭 필요한 기능부터 만들어 봐요.\n3. 직접 써 보며 불편한 점을 고쳐요.",
            "gemini": "서로 다른 관점으로 살펴보면 좋아요.\n\n먼저 원하는 결과와 제약을 나눠 적어 보세요. 선택지를 비교한 뒤, 가장 작은 실험으로 확인해 보세요.",
            "claude": "좋은 출발점은 구체적인 질문이에요.\n\n누가, 어떤 상황에서, 무엇이 필요한지 생각해 보세요. 답을 정하기 전에 가정을 확인하면 다음 단계가 더 분명해져요.",
        }
        if self.scenario == "unsafe":
            return '<script>window.pwned=true</script> javascript:alert(1)\n' + ('긴 응답 예시 ' * 1800)
        return f"[Demo · 실제 모델의 답변이 아닙니다]\n\n{perspectives[model]}\n\n입력한 질문\n{prompt}"
