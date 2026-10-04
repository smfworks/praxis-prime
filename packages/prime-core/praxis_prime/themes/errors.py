"""Machine-readable theme errors.

Lint and the HTTP API both emit these. ``code`` is stable. ``fix`` tells an
author (or a model) what to change.

Addendum A §1.4 and §1.5.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ThemeIssue:
    """One problem a theme author can act on."""

    code: str
    message: str
    path: str = ""
    fix: str = ""

    def to_json(self) -> dict[str, str]:
        body = {"code": self.code, "message": self.message}
        if self.path:
            body["path"] = self.path
        if self.fix:
            body["fix"] = self.fix
        return body


class ThemeError(Exception):
    """A theme was refused. ``issues`` is empty for a single operational failure."""

    def __init__(self, message: str, issues: tuple[ThemeIssue, ...] = ()) -> None:
        super().__init__(message)
        self.issues = issues

    def to_json(self) -> dict[str, object]:
        return {
            "ok": False,
            "error": {
                "code": "theme_invalid",
                "message": str(self),
                "issues": [issue.to_json() for issue in self.issues],
            },
        }
