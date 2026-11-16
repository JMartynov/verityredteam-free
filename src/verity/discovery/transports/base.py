"""Abstract base class for dynamic MCP capability discovery transports."""

from __future__ import annotations

import abc

from verity.discovery.models import DiscoveredServerConfig, LiveServerCapability


class BaseDiscoveryTransport(abc.ABC):
    """Abstract interface for inspecting live MCP server tool and prompt capabilities."""

    def __init__(self, timeout_seconds: float = 5.0) -> None:
        self.timeout_seconds = timeout_seconds

    @abc.abstractmethod
    def inspect(self, config: DiscoveredServerConfig) -> LiveServerCapability:
        """Connect to the target MCP server, list capabilities, and disconnect safely."""
        raise NotImplementedError
