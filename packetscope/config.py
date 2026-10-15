"""Deployment configuration and privacy copy for the HTTP application."""

from __future__ import annotations

from dataclasses import dataclass
import os


LOCAL_MODE = "local"
PUBLIC_DEMO_MODE = "public-demo"
DEPLOYMENT_MODES = frozenset({LOCAL_MODE, PUBLIC_DEMO_MODE})


def resolve_deployment_mode(value: str | None = None) -> str:
    """Return a validated deployment mode, defaulting to the private server."""
    raw = value if value is not None else os.environ.get("PACKETSCOPE_DEPLOYMENT_MODE", LOCAL_MODE)
    mode = str(raw).strip().lower().replace("_", "-")
    if mode not in DEPLOYMENT_MODES:
        allowed = ", ".join(sorted(DEPLOYMENT_MODES))
        raise ValueError(f"deployment mode must be one of: {allowed}")
    return mode


def format_bytes(value: int) -> str:
    """Format a bounded byte limit for the browser without losing precision."""
    if value >= 1024 * 1024 and value % (1024 * 1024) == 0:
        return f"{value // (1024 * 1024)} MiB"
    if value >= 1024 and value % 1024 == 0:
        return f"{value // 1024} KiB"
    return f"{value} bytes"


@dataclass(frozen=True)
class DeploymentConfig:
    mode: str = LOCAL_MODE

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", resolve_deployment_mode(self.mode))

    @property
    def local_only(self) -> bool:
        return self.mode == LOCAL_MODE

    @property
    def public_demo(self) -> bool:
        return self.mode == PUBLIC_DEMO_MODE

    @property
    def privacy_notice(self) -> str:
        if self.public_demo:
            return (
                "Warning: uploaded captures are transmitted to and processed by "
                "this hosted public demo server. Do not upload confidential data."
            )
        return "Captures are processed by this local server and are not sent to a hosted service."

    @property
    def ui_title(self) -> str:
        return "PacketScope — hosted public demo" if self.public_demo else "PacketScope — local protocol workbench"

    @property
    def ui_eyebrow(self) -> str:
        return "PUBLIC DEMO / EVIDENCE FIRST" if self.public_demo else "LOCAL / PRIVATE / EVIDENCE FIRST"

    @property
    def ui_badge(self) -> str:
        return "Hosted public demo · uploads are transmitted to this server" if self.public_demo else "Local/private · no cloud · no telemetry"

    @property
    def ui_analyze_label(self) -> str:
        return "Upload to demo server" if self.public_demo else "Analyze locally"

    @property
    def ui_ready_status(self) -> str:
        if self.public_demo:
            return "Ready for a file; uploads are sent to this hosted demo server."
        return "Ready for a local file."


def deployment_from_env() -> DeploymentConfig:
    return DeploymentConfig(resolve_deployment_mode())
