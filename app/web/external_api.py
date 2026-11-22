# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""AI round without an API key, file channel: download the brief, paste the model's answer back (app/external.py)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel

from ..external import MAX_ANSWER
from ..i18n import t
from .common import actor, ui_lang
from .common import env as _env
from .common import runtime as _rt

router = APIRouter()


class StartReq(BaseModel):
    hours: int | None = None


@router.post("/api/e/{env_id}/external/start")
async def external_start(request: Request, env_id: str, body: StartReq):
    """Collects the period now (like a built-in round) and returns the masked brief as a Markdown file."""
    _env(request, env_id)
    if body.hours is not None and not 1 <= body.hours <= 24 * 14:
        raise HTTPException(400, t(ui_lang(request), "err.hours"))
    try:
        r = await _rt(request).external_start(env_id, "file", actor=actor(request), hours=body.hours)
    except RuntimeError as e:
        raise HTTPException(409, str(e)) from e
    return Response(r["brief"], media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="occultera-{r["run_id"]}.md"',
                             "X-Occultera-Run": r["run_id"]})


class AnswerReq(BaseModel):
    text: str


@router.post("/api/e/{env_id}/external/{run_id}")
async def external_answer(request: Request, env_id: str, run_id: str, body: AnswerReq):
    _env(request, env_id)
    if len(body.text) > MAX_ANSWER:
        raise HTTPException(413, "too large")
    try:
        run = await _rt(request).external_submit(env_id, run_id, body.text, actor=actor(request), client="file")
    except KeyError as e:
        raise HTTPException(404, "run not found") from e
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return {"run_id": run["run_id"], "status": run["status"], "findings": len(run.get("findings") or []),
            "proposals": len(run.get("proposals") or []), "ai_error": run.get("ai_error")}
