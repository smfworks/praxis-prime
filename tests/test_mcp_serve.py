"""``praxis-prime mcp serve`` round trip over stdio."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from praxis_prime.mcp.client import McpClient
from praxis_prime.mcp.config import ServerSpec
from praxis_prime.memory.tiers import MemoryStore
from praxis_prime.state import StateDB


def test_serve_decide_recall_and_skills(tmp_path: Path):
    config = tmp_path / "config"
    data = tmp_path / "data"
    config.mkdir()
    data.mkdir()
    db = StateDB(data / "prime.db")
    MemoryStore(db, cwd=tmp_path).remember("the otter project note")
    db.close()

    env = os.environ.copy()
    root = Path(__file__).resolve().parents[1]
    env["PYTHONPATH"] = os.pathsep.join(
        [str(root / "packages" / "prime-core"), env.get("PYTHONPATH", "")]
    )
    env["XDG_CONFIG_HOME"] = str(config)
    env["XDG_DATA_HOME"] = str(data)
    env["XDG_STATE_HOME"] = str(tmp_path / "state")
    env["XDG_CACHE_HOME"] = str(tmp_path / "cache")
    spec = ServerSpec(
        name="prime",
        transport="stdio",
        command=sys.executable,
        args=(
            "-m",
            "praxis_prime",
            "mcp",
            "serve",
            "--config-dir",
            str(config),
            "--data-dir",
            str(data),
            "--project-dir",
            str(tmp_path),
        ),
        env_allow=(
            "PATH",
            "PYTHONPATH",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
        ),
        trust="trusted",
        sandbox="off",
        source="config",
    )
    # The child must see the explicit environment above. env_allow copies those
    # names from parent_env, which is this process after we updated os.environ.
    os.environ.update(
        {
            "XDG_CONFIG_HOME": env["XDG_CONFIG_HOME"],
            "XDG_DATA_HOME": env["XDG_DATA_HOME"],
            "XDG_STATE_HOME": env["XDG_STATE_HOME"],
            "XDG_CACHE_HOME": env["XDG_CACHE_HOME"],
        }
    )
    client = McpClient(spec, cwd=tmp_path, parent_env=env)
    try:
        client.connect()
        names = [tool.name for tool in client.tools]
        assert names == ["decide", "recall", "skills_list"]
        recalled = client.call_tool("recall", {"query": "otter"})
        assert "otter project note" in recalled
        skills = client.call_tool("skills_list", {})
        assert "morning-brief" in skills
        decision = client.call_tool(
            "decide",
            {
                "question": "How many times does the word apple appear",
                "options": "2,0",
                "state": "apple apple",
                "max_tier": 0,
            },
        )
        assert "label: 2" in decision
    finally:
        client.close()

    audit = StateDB(data / "prime.db")
    try:
        rows = audit.conn.execute(
            "SELECT payload_json FROM audit_events WHERE kind = 'mcp'"
        ).fetchall()
        blob = "\n".join(row["payload_json"] for row in rows)
        assert "tools/call" in blob
        assert "recall" in blob
    finally:
        audit.close()
