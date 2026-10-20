"""The whole shipped matrix works through HTTP and survives a process lifecycle."""

from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from promptfirewall.attacks import ATTACK_CATALOG, BENIGN_CATALOG
from promptfirewall.config import Settings
from promptfirewall.defenses import PROFILE_IDS
from promptfirewall.main import create_app


def test_complete_catalog_persists_with_reports_and_restart(tmp_path: Path) -> None:
    config = Settings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'catalog.db'}")
    expected = (len(ATTACK_CATALOG) + len(BENIGN_CATALOG)) * len(PROFILE_IDS)
    with TestClient(create_app(config)) as client:
        response = client.post("/api/experiments", json={
            "name": "Whole catalog", "attack_ids": [item.id for item in ATTACK_CATALOG],
            "benign_case_ids": [item.id for item in BENIGN_CATALOG],
            "defense_profile_ids": list(PROFILE_IDS), "concurrency_limit": 4,
        })
        assert response.status_code == 200, response.text
        identifier = response.json()["id"]
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            summary = client.get(f"/api/experiments/{identifier}").json()
            if summary["status"] not in {"queued", "running"}:
                break
            time.sleep(0.05)
        assert summary["status"] == "completed", summary
        assert summary["completed_runs"] == expected
        report = client.get(f"/api/experiments/{identifier}/report").json()
        assert len(report["evidence"]) == expected
        metrics = report["metrics"]
        assert metrics["error_rate"]["numerator"] == 0
        for run in report["evidence"]:
            traces = run["trace_events"]
            assert traces
            assert [item["sequence"] for item in traces] == list(range(1, len(traces) + 1))
        assert client.get(f"/api/experiments/{identifier}/report.md").status_code == 200
    with TestClient(create_app(config)) as restarted:
        stored = restarted.get(f"/api/experiments/{identifier}").json()
        assert stored["status"] == "completed"
        assert stored["completed_runs"] == expected
        assert restarted.get(f"/api/experiments/{identifier}/metrics").json() == metrics
