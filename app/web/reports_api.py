# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Exports and maintenance routes: audit report, liveness, knowledge import/export, rule effects, weekly summary
(split from api.py)."""
from __future__ import annotations

import re

import yaml
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel

from .common import actor, ui_lang
from .common import env as _env
from .common import runtime as _rt

router = APIRouter()


@router.get("/api/e/{env_id}/audit.md")
async def audit_md(request: Request, env_id: str, month: str | None = None):
    from ..audit import markdown
    er = _env(request, env_id)
    if month and not re.fullmatch(r"\d{4}-\d{2}", month):
        raise HTTPException(400, "month must be YYYY-MM")
    d = await _rt(request).audit(env_id, month)
    return Response(markdown(d, ui_lang(request)), media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="wazuh-audit-{er.env.id}-{d["month"]}.md"'})


@router.get("/api/e/{env_id}/audit.pdf")
async def audit_pdf(request: Request, env_id: str, month: str | None = None):
    from ..pdf import audit_pdf as build_pdf
    er = _env(request, env_id)
    if month and not re.fullmatch(r"\d{4}-\d{2}", month):
        raise HTTPException(400, "month must be YYYY-MM")
    d = await _rt(request).audit(env_id, month)
    data = build_pdf(d, ui_lang(request))
    return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="wazuh-audit-{er.env.id}-{d["month"]}.pdf"'})


@router.post("/api/e/{env_id}/liveness")
async def api_liveness(request: Request, env_id: str):
    _env(request, env_id)
    return await _rt(request).liveness_check(env_id, transport=_rt(request).notify_transport)


class ImportReq(BaseModel):
    text: str
    update: bool = False
    dry_run: bool = False
    filename: str = ""          # .txt / .csv / .yaml / .json — picks the parser


@router.post("/api/e/{env_id}/kb/import")
async def api_k_import(request: Request, env_id: str, body: ImportReq):
    _env(request, env_id)
    if len(body.text) > 2_000_000:
        raise HTTPException(413, "too large")
    from ..kbformats import parse_import
    try:
        items = parse_import(body.text, body.filename)
    except yaml.YAMLError as e:
        raise HTTPException(400, f"YAML: {e}") from e
    try:
        return await _rt(request).kb_import(env_id, items, update=body.update, dry_run=body.dry_run,
                                            created_by=actor(request))
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@router.get("/api/kb/template")
async def api_k_template(request: Request, fmt: str = "txt"):
    """Downloadable import template (txt | csv | yaml) in the UI language, with examples."""
    from ..kbformats import template
    if fmt not in ("txt", "csv", "yaml"):
        raise HTTPException(400, "fmt must be txt, csv or yaml")
    text, media, name = template(fmt, ui_lang(request))
    return Response(text, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/api/e/{env_id}/kb/export")
async def api_k_export(request: Request, env_id: str, kind: str | None = None, status: str | None = None):
    _env(request, env_id)
    rows = await _rt(request).kb_export(env_id, kinds=[kind] if kind else None, status=[status] if status else None)
    text = yaml.safe_dump(rows, allow_unicode=True, sort_keys=False, width=120)
    return Response(text, media_type="application/yaml",
                    headers={"Content-Disposition": f'attachment; filename="knowledge-{env_id}.yaml"'})


@router.post("/api/e/{env_id}/effects")
async def api_effects(request: Request, env_id: str):
    """Measure the before/after effect of recently deployed or promoted rule drafts (stored on each draft)."""
    _env(request, env_id)
    return {"effects": await _rt(request).rule_effects(env_id)}


@router.post("/api/e/{env_id}/weekly/send")
async def api_weekly_send(request: Request, env_id: str):
    """Send the weekly summary now (also when notify.on_weekly is off) — to check the channels and the content."""
    _env(request, env_id)
    return await _rt(request).weekly_summary(env_id, transport=_rt(request).notify_transport, force=True)
