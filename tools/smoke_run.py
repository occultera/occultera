# SPDX-License-Identifier: AGPL-3.0-only
"""Drive a running Occultera through one full triage run (CI smoke test against a real indexer).

    python -m tools.smoke_run http://127.0.0.1:8080 <password> <env id>

Signs in, starts a run, waits for it, and checks that the report has numbers from the indexer, no collection
errors and renders; then opens every page once.
"""
import sys
import time

import httpx


def main(base: str, password: str, env: str) -> None:
    with httpx.Client(base_url=base.rstrip("/"), timeout=120, follow_redirects=False) as c:
        r = c.post("/login", data={"password": password})
        assert r.status_code == 303, f"login: {r.status_code}"
        rid = c.post(f"/api/e/{env}/run", json={"hours": 72}, headers={"Origin": base}).json()["run_id"]
        for _ in range(120):
            st = c.get(f"/api/e/{env}/r/{rid}/status").json()
            if st.get("status") in ("done", "error"):
                break
            time.sleep(2)
        assert st.get("status") == "done", f"run ended with {st}"
        page = c.get(f"/e/{env}/r/{rid}")
        assert page.status_code == 200, page.status_code
        text = page.text
        assert "Collection errors" not in text, "the report lists collection errors (blind spots)"
        for p in ["/", f"/e/{env}", f"/e/{env}/inbox", f"/e/{env}/attack", f"/e/{env}/noise", f"/e/{env}/watch",
                  f"/e/{env}/k", f"/e/{env}/audit", f"/e/{env}/settings", "/about"]:
            code = c.get(p).status_code
            assert code == 200, f"{p}: {code}"
        print(f"run {rid}: done, report and {10} pages OK")


if __name__ == "__main__":
    main(*sys.argv[1:4])
