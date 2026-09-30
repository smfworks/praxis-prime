"""Wire settings, the router, tools, policy, and the session database."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from praxis_prime.approvals.gate import ApprovalGate, Approver
from praxis_prime.audit.log import AuditLog
from praxis_prime.decide.engine import DecisionEngine, build_engine
from praxis_prime.decide.screen import ActionScreener
from praxis_prime.decide.tool import install_decide_tool
from praxis_prime.loop.engine import AgentLoop
from praxis_prime.loop.prompt import session_preamble
from praxis_prime.memory.store import SessionStore
from praxis_prime.paths import config_dir
from praxis_prime.policy.engine import PolicyEngine
from praxis_prime.router.factory import build_router
from praxis_prime.router.router import ChatProvider, ModelRouter
from praxis_prime.router.settings import Settings, load_settings
from praxis_prime.router.types import parse_model_spec
from praxis_prime.state import StateDB, default_db_path
from praxis_prime.tools.builtin import builtin_registry
from praxis_prime.tools.registry import ToolRegistry


@dataclass
class Runtime:
    settings: Settings
    router: ModelRouter
    registry: ToolRegistry
    policy: PolicyEngine
    gate: ApprovalGate
    db: StateDB
    store: SessionStore
    audit: AuditLog
    engine: DecisionEngine
    screener: ActionScreener
    cwd: Path

    def close(self) -> None:
        self.engine.labels.close()
        self.db.close()

    def set_model(self, spec: str) -> str:
        ref = parse_model_spec(spec)
        if ref.provider not in self.router.providers:
            known = ", ".join(sorted(self.router.providers))
            raise ValueError(f"no adapter for {ref.provider}. Known: {known}.")
        self.router.use_primary(ref)
        return ref.spec()

    def open_loop(self, session_id: str | None = None) -> tuple[str, AgentLoop]:
        preamble = session_preamble(str(self.cwd))
        if session_id:
            if not self.store.exists(session_id):
                raise LookupError(f"no session {session_id}")
            history = self.store.load(session_id)
            active_preamble = "" if history else preamble
        else:
            history = []
            active_preamble = preamble
            session_id = self.store.create(
                model=self.router.primary.spec(),
                preamble=preamble,
            )
        loop = AgentLoop(
            router=self.router,
            registry=self.registry,
            policy=self.policy,
            gate=self.gate,
            cwd=self.cwd,
            max_iterations=self.settings.max_iterations,
            mode=self.settings.mode,
            history=history,
            preamble=active_preamble,
            store=self.store,
            audit=self.audit,
            session_id=session_id,
            screener=self.screener,
        )
        return session_id, loop


def build_runtime(
    *,
    env: Mapping[str, str] | None = None,
    config_path: Path | None = None,
    data_path: Path | None = None,
    cwd: Path | None = None,
    approver: Approver | None = None,
    providers: dict[str, ChatProvider] | None = None,
    model: str | None = None,
    registry: ToolRegistry | None = None,
) -> Runtime:
    if env is None and config_path is None:
        settings = load_settings()
    else:
        settings = load_settings(
            {} if env is None else env,
            config_path=config_path,
        )
    router = build_router(settings, providers)
    if model:
        ref = parse_model_spec(model)
        router.use_primary(ref)
    path = data_path or default_db_path(env)
    db = StateDB(path)
    audit = AuditLog(db)
    tools = registry or builtin_registry()
    environ = os.environ if env is None else env
    if config_path is not None:
        resolved_config = config_path
    else:
        resolved_config = config_dir(environ) / "config.toml"
    engine = build_engine(
        config_path=resolved_config,
        data_root=path.parent,
        router=router,
        audit=audit,
        approver=approver,
        dials=settings.dials,
    )
    install_decide_tool(tools, engine)
    return Runtime(
        settings=settings,
        router=router,
        registry=tools,
        policy=PolicyEngine(settings.dials),
        gate=ApprovalGate(approver),
        db=db,
        store=SessionStore(db),
        audit=audit,
        engine=engine,
        screener=ActionScreener(engine, enabled=engine.config.prescreen),
        cwd=cwd or Path.cwd(),
    )
