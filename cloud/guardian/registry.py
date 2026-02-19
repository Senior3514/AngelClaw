"""AngelClaw -- Angel Legion Sub-Agent Registry.

Dynamic registry for managing the Angel Legion.  Allows the Seraph
(orchestrator) to scale to N agents without hard-coding each one.

V2.2 upgrades:
  - Agent deregistration & replacement
  - Health scoring across the Legion
  - Cloud/Identity warden types
  - Search by permission
  - Fleet-wide health summary with degradation detection
"""

from __future__ import annotations

import logging

from cloud.guardian.base_agent import SubAgent
from cloud.guardian.models import AgentStatus, AgentType, Permission

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
        # V2.2 — new warden types
        AgentType.CLOUD,
        AgentType.IDENTITY,
        # V2.4 — Fortress wardens
        AgentType.COMPLIANCE,
        AgentType.API_SECURITY,
        # V2.5 — Plugin wardens
        AgentType.PLUGIN,
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

    # V2.2 — Deregistration
    def deregister(self, agent_id: str) -> bool:
        """Remove an agent from the registry. Returns True if found."""
        agent = self._agents.pop(agent_id, None)
        if not agent:
            return False
        type_list = self._by_type.get(agent.agent_type, [])
        self._by_type[agent.agent_type] = [a for a in type_list if a.agent_id != agent_id]
        logger.info("[REGISTRY] Deregistered %s (%s)", agent_id, agent.agent_type.value)
        return True

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

    # V2.2 — Search by permission
    def agents_with_permission(self, perm: Permission) -> list[SubAgent]:
        """Return all agents that hold a specific permission."""
        return [a for a in self._agents.values() if perm in a.permissions]

    # V2.2 — Healthy wardens only
    def healthy_wardens(self) -> list[SubAgent]:
        """Return wardens that are not stopped or errored."""
        return [
            a for a in self.all_wardens()
            if a.status not in (AgentStatus.STOPPED, AgentStatus.ERROR)
        ]

    @property
    def count(self) -> int:
        """Total number of registered agents."""
        return len(self._agents)

    # ------------------------------------------------------------------
    # V2.2 — Health scoring
    # ------------------------------------------------------------------

    def fleet_health_score(self) -> float:
        """Compute a 0.0-1.0 health score for the entire fleet.

        Based on: agent availability, success rates, and error states.
        """
        agents = self.all_agents()
        if not agents:
            return 1.0

        score_sum = 0.0
        for a in agents:
            if a.status == AgentStatus.STOPPED:
                score_sum += 0.0
            elif a.status == AgentStatus.ERROR:
                score_sum += 0.2
            elif a.status == AgentStatus.BUSY:
                score_sum += 0.9 * a.success_rate
            else:
                score_sum += a.success_rate

        return round(score_sum / len(agents), 3)

    def degraded_agents(self) -> list[SubAgent]:
        """Return agents in ERROR state that may need recovery."""
        return [a for a in self._agents.values() if a.status == AgentStatus.ERROR]

    def recover_degraded(self) -> int:
        """Attempt to reset all degraded agents. Returns count recovered."""
        recovered = 0
        for agent in self.degraded_agents():
            agent.reset_health()
            recovered += 1
        if recovered:
            logger.info("[REGISTRY] Recovered %d degraded agent(s)", recovered)
        return recovered

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
            # V2.2 — health metrics
            "fleet_health": self.fleet_health_score(),
            "degraded_count": len(self.degraded_agents()),
        }
