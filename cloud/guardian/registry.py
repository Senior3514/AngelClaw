"""AngelClaw -- Angel Legion Sub-Agent Registry.

Dynamic registry for managing the Angel Legion.  Allows the Seraph
(orchestrator) to scale to N agents without hard-coding each one.
"""

from __future__ import annotations

import logging

from cloud.guardian.base_agent import SubAgent
from cloud.guardian.models import AgentStatus, AgentType

logger = logging.getLogger("angelgrid.cloud.guardian.registry")

# Agent types that perform detection (warden role)
WARDEN_TYPES: frozenset[AgentType] = frozenset(
    {
        AgentType.WARDEN,
        AgentType.NETWORK,
        AgentType.SECRETS,
        AgentType.TOOLCHAIN,
        AgentType.BEHAVIOR,
        AgentType.TIMELINE,
        AgentType.BROWSER,
    }
)


class AgentRegistry:
    """Registry of all active sub-agents in the Angel Legion."""

    def __init__(self) -> None:
        self._agents: dict[str, SubAgent] = {}
        self._by_type: dict[AgentType, list[SubAgent]] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, agent: SubAgent) -> None:
        """Register a sub-agent into the Legion."""
        self._agents[agent.agent_id] = agent
        self._by_type.setdefault(agent.agent_type, []).append(agent)
        logger.info(
            "[REGISTRY] Registered %s (%s)",
            agent.agent_id,
            agent.agent_type.value,
        )

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, agent_id: str) -> SubAgent | None:
        """Get an agent by its unique ID."""
        return self._agents.get(agent_id)

    def get_by_type(self, agent_type: AgentType) -> list[SubAgent]:
        """Get all agents of a specific type."""
        return list(self._by_type.get(agent_type, []))

    def get_first(self, agent_type: AgentType) -> SubAgent | None:
        """Get the first agent of a type, or None."""
        agents = self._by_type.get(agent_type, [])
        return agents[0] if agents else None

    def all_agents(self) -> list[SubAgent]:
        """Return all registered agents."""
        return list(self._agents.values())

    def all_wardens(self) -> list[SubAgent]:
        """Return all agents with a detection (warden) role."""
        return [a for a in self._agents.values() if a.agent_type in WARDEN_TYPES]

    def active_agents(self) -> list[SubAgent]:
        """Return agents that are not stopped or errored."""
        return [
            a
            for a in self._agents.values()
            if a.status not in (AgentStatus.STOPPED, AgentStatus.ERROR)
        ]

    @property
    def count(self) -> int:
        """Total number of registered agents."""
        return len(self._agents)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def shutdown_all(self) -> None:
        """Gracefully shut down every agent."""
        for agent in self._agents.values():
            await agent.shutdown()
        logger.info("[REGISTRY] All %d agents shut down", len(self._agents))

    # ------------------------------------------------------------------
    # Info / status
    # ------------------------------------------------------------------

    def info_all(self) -> dict[str, dict]:
        """Return info dicts for all agents, keyed by agent_id."""
        return {a.agent_id: a.info() for a in self._agents.values()}

    def summary(self) -> dict:
        """Return a concise Legion summary."""
        by_status: dict[str, int] = {}
        by_type: dict[str, int] = {}
        for a in self._agents.values():
            by_status[a.status.value] = by_status.get(a.status.value, 0) + 1
            by_type[a.agent_type.value] = by_type.get(a.agent_type.value, 0) + 1
        return {
            "total_agents": len(self._agents),
            "wardens": len(self.all_wardens()),
            "by_status": by_status,
            "by_type": by_type,
        }
