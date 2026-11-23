"""The next window starts after the last run whose AI analysis succeeded, not after a failed one."""
import asyncio

from app.store import MemoryStore, Repo


def test_last_success_skips_runs_without_ai():
    async def go():
        repo = Repo(MemoryStore(), "e1")
        await repo.save_run({"run_id": "a", "env": "e1", "status": "done", "started_at": "2026-11-20T05:00:00.000Z",
                             "window": {"to": "2026-11-20T05:00:00.000Z"}})
        await repo.save_run({"run_id": "b", "env": "e1", "status": "done", "started_at": "2026-11-23T05:00:00.000Z",
                             "window": {"to": "2026-11-23T05:00:00.000Z"}, "ai_error": "LLM 402"})
        assert (await repo.last_success())["run_id"] == "a"
        await repo.save_run({"run_id": "c", "env": "e1", "status": "done", "started_at": "2026-11-23T07:30:00.000Z",
                             "window": {"to": "2026-11-23T07:30:00.000Z"}})
        assert (await repo.last_success())["run_id"] == "c"
    asyncio.run(go())
