import asyncio
import copy
import logging
import os
import time
import uuid
from .runners.process import RunnerError

ACTIVE = {"waiting", "running"}
ERRORS = {"timeout", "cli_failed", "output_limit", "invalid_output", "auth_required", "rate_limited", "provider_unavailable", "cancelled", "queue_timeout", "network_unavailable"}
AUDIT = logging.getLogger("uvicorn.error")


class ServiceError(Exception):
    def __init__(self, code, status=409):
        self.code, self.status = code, status


class Store:
    def __init__(self, runner, mode="demo", max_active=6, max_runs=30, ttl=3600, timeout=90, queue_timeout=120):
        self.runner, self.mode = runner, mode
        self.max_active, self.max_runs, self.ttl = max_active, max_runs, ttl
        self.timeout, self.queue_timeout = timeout, queue_timeout
        self.runs, self.tasks = {}, set()
        self.lock = asyncio.Lock()
        self.slots, self.agy = asyncio.Semaphore(3), asyncio.Semaphore(1)
        self.closed = False

    def cleanup(self):
        now = time.time()
        for key, run in list(self.runs.items()):
            if not any(x["status"] in ACTIVE for x in run["models"].values()) and now - run["updated_at"] > self.ttl:
                del self.runs[key]

    def capacity(self, count):
        active = sum(x["status"] in ACTIVE for r in self.runs.values() for x in r["models"].values())
        if self.closed or active + count > self.max_active:
            raise ServiceError("busy", 429)

    def attempt(self, number):
        return dict(attempt_id=number, status="waiting", response=None, error=None,
                    queued_at=time.time(), started_at=None, finished_at=None)

    def audit(self, key, model, number, status):
        # Opt-in, fixed metadata only. Never format a prompt, response or exception.
        if os.environ.get("UNION_AUDIT_LOG") != "1":
            return
        cli = {"gpt": "Codex", "gemini": "Antigravity", "claude": "Antigravity"}.get(model)
        if cli is None or self.mode not in {"live", "demo"}:
            return
        if status not in {"waiting", "running", "complete", "failed", "timeout"}:
            return
        if len(key) != 32 or any(c not in "0123456789abcdef" for c in key):
            return
        if type(number) is not int or number < 1:
            return
        AUDIT.info("UC %s mode=%s run=%s model=%s cli=%s attempt=%d status=%s",
                   time.strftime("%H:%M:%S"), self.mode, key, model, cli, number, status)

    async def create(self, prompt, models):
        async with self.lock:
            self.cleanup()
            self.capacity(len(models))
            if len(self.runs) >= self.max_runs:
                raise ServiceError("run_limit", 429)
            key = uuid.uuid4().hex
            self.runs[key] = dict(run_id=key, prompt=prompt, mode=self.mode, created_at=time.time(), updated_at=time.time(),
                                  models={m: self.attempt(1) for m in models})
            for m in models:
                self.launch(key, m, 1)
            return copy.deepcopy(self.runs[key])

    def get(self, key):
        self.cleanup()
        if key not in self.runs:
            raise ServiceError("run_missing", 404)
        return copy.deepcopy(self.runs[key])

    async def retry(self, key, model):
        async with self.lock:
            run = self.get(key)
            old = run["models"].get(model)
            if not old or old["status"] not in {"failed", "timeout"}:
                raise ServiceError("retry_conflict")
            self.capacity(1)
            number = old["attempt_id"] + 1
            self.runs[key]["models"][model] = self.attempt(number)
            self.runs[key]["updated_at"] = time.time()
            self.launch(key, model, number)
            return self.get(key)

    def launch(self, key, model, number):
        self.audit(key, model, number, "waiting")
        task = asyncio.create_task(self.work(key, model, number))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    def publish(self, key, model, number, **changes):
        entry = self.runs[key]["models"][model]
        if entry["attempt_id"] != number or entry["status"] not in ACTIVE:
            return False
        entry.update(changes)
        self.runs[key]["updated_at"] = time.time()
        if "status" in changes:
            self.audit(key, model, number, entry["status"])
        return True

    async def work(self, key, model, number):
        # Conservative agy serialization pending actual shared-session feasibility.
        gate = self.agy if model in {"gemini", "claude"} else asyncio.Semaphore(1)
        acquired_gate = acquired_slot = False
        try:
            try:
                async with asyncio.timeout(self.queue_timeout):
                    await gate.acquire()
                    acquired_gate = True
                    await self.slots.acquire()
                    acquired_slot = True
            except TimeoutError:
                raise RunnerError("queue_timeout") from None
            self.publish(key, model, number, status="running", started_at=time.time())
            async with asyncio.timeout(self.timeout):
                result = await self.runner(model, self.runs[key]["prompt"], number)
            if not isinstance(result, str) or not result.strip():
                raise RunnerError("invalid_output")
            if len(result.encode()) > 65536:
                raise RunnerError("output_limit")
            self.publish(key, model, number, status="complete", response=result, finished_at=time.time())
        except (Exception, asyncio.CancelledError) as exc:
            code = "timeout" if isinstance(exc, TimeoutError) else "cancelled" if isinstance(exc, asyncio.CancelledError) else getattr(exc, "code", "cli_failed")
            if code not in ERRORS:
                code = "cli_failed"
            self.publish(key, model, number, status="timeout" if code == "timeout" else "failed", error=code, finished_at=time.time())
        finally:
            if acquired_slot:
                self.slots.release()
            if acquired_gate:
                gate.release()

    async def close(self):
        self.closed = True
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for run in self.runs.values():
            for entry in run["models"].values():
                if entry["status"] in ACTIVE:
                    entry.update(status="failed", error="cancelled", finished_at=time.time())
