"""Bounded subprocess transport. No provider is enabled by this module."""
import asyncio
import os
import signal
import ctypes


class RunnerError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


async def stop_group(proc):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass
        if sig == signal.SIGTERM:
            await asyncio.sleep(0.15)
    await proc.wait()
    # Reap only this group, never unrelated asyncio subprocesses.
    for _ in range(50):
        try:
            pid, _ = os.waitpid(-proc.pid, os.WNOHANG)
        except ChildProcessError:
            break
        if pid == 0:
            await asyncio.sleep(.01)


async def execute(argv, prompt, cwd, *, timeout=90, limit=262144, before_stop=None, classify_failure=None, observe=None):
    if ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) != 0:
        raise RunnerError("process_isolation_failed")
    # An allowlist environment prevents inherited API keys, loader hooks and proxies.
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    proc = await asyncio.create_subprocess_exec(
        *argv, cwd=cwd, env=env, start_new_session=True,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def drain(stream):
        data = bytearray()
        while chunk := await stream.read(8192):
            if len(data) + len(chunk) > limit:
                raise RunnerError("output_limit")
            data.extend(chunk)
        return bytes(data)

    async def feed():
        try:
            proc.stdin.write(prompt.encode("utf-8"))
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            proc.stdin.close()

    jobs = [asyncio.create_task(drain(proc.stdout)), asyncio.create_task(drain(proc.stderr)),
            asyncio.create_task(feed()), asyncio.create_task(proc.wait())]
    try:
        async with asyncio.timeout(timeout):
            stdout, stderr, _, code = await asyncio.gather(*jobs)
        if observe is not None:
            observe(stdout, stderr)
        if code:
            error = classify_failure(stdout, stderr) if classify_failure is not None else 'cli_failed'
            # Callers can classify in memory, but cannot export arbitrary stderr.
            if error not in {'cli_failed', 'auth_required', 'rate_limited', 'network_unavailable'}:
                error = 'cli_failed'
            raise RunnerError(error)
        return stdout
    except TimeoutError:
        raise RunnerError("timeout") from None
    finally:
        for job in jobs:
            job.cancel()
        await asyncio.gather(*jobs, return_exceptions=True)
        # Continue discarding during kill/reap. A paused pipe can otherwise make
        # Process.wait() hang even after the process has received SIGKILL.
        async def discard(stream):
            while await stream.read(8192):
                pass
        drains = [asyncio.create_task(discard(proc.stdout)), asyncio.create_task(discard(proc.stderr))]
        try:
            try:
                if before_stop is not None:
                    await before_stop()
            finally:
                await stop_group(proc)
            await asyncio.gather(*drains)
        finally:
            for task in drains:
                task.cancel()
            await asyncio.gather(*drains, return_exceptions=True)
        await asyncio.sleep(0)
