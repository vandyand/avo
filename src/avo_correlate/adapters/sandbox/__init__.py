"""Sandbox implementations."""

from avo_correlate.adapters.sandbox.docker import DockerSandbox
from avo_correlate.adapters.sandbox.local import LocalProcessSandbox

__all__ = ["DockerSandbox", "LocalProcessSandbox"]
