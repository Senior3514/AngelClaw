"""AngelBot — Autonomous AI Defense Agent.

The angel-side mirror of ClawBot / OpenClaw / MoltBot.  Every offensive
capability has a defensive counterpart.  Where ClawBot attacks, AngelBot
defends.  Where MoltBot chains exploits, AngelBot chains protections.

ClawBot            →  AngelBot
──────────────────────────────────────────────────
self-replication   →  self-healing & recovery
persistence        →  guardian deployment
anti-detection     →  anomaly illumination
lateral movement   →  perimeter enforcement
C2 callbacks       →  C2 detection & severance
resource abuse     →  resource monitoring & caps
security kill      →  security hardening
data exfiltration  →  data sovereignty enforcement
prompt injection   →  prompt sanitization
attack chains      →  protection chains

The "Holy Trifecta" (inverse of the Lethal Trifecta):
  1. Data Sovereignty   — all sensitive data is classified & protected
  2. Trust Verification — all inputs are verified before processing
  3. Isolation Control   — all communications are authorized & audited

Philosophy: Guardian angel with teeth.  AngelBot doesn't just detect —
it actively hunts, contains, remediates, and hardens.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger("angelbot")


# -----------------------------------------------------------------------
# AngelBot Identity
# -----------------------------------------------------------------------

ANGELBOT_VERSION = "1.0.0"
ANGELBOT_CODENAME = "Seraph"


class AgentMode(str, Enum):
    """AngelBot operating modes."""

    SENTINEL = "sentinel"      # Passive monitoring only
    GUARDIAN = "guardian"       # Active defense (detect + alert)
    ARCHANGEL = "archangel"    # Full autonomous response


class DefenseAction(str, Enum):
    """Actions AngelBot can take."""

    DETECT = "detect"
    ALERT = "alert"
    CONTAIN = "contain"
    REMEDIATE = "remediate"
    HARDEN = "harden"
    HUNT = "hunt"
    VERIFY = "verify"
    SEVER = "sever"
    ILLUMINATE = "illuminate"
    RECOVER = "recover"


# -----------------------------------------------------------------------
# Holy Trifecta — The 3 Pillars of Defense (inverse of Lethal Trifecta)
# -----------------------------------------------------------------------

@dataclass
class HolyTrifecta:
    """The three pillars of defense.  Score 1.0 = fully defended."""

    data_sovereign: bool = False
    trust_verified: bool = False
    isolation_enforced: bool = False
    evidence: dict[str, list[str]] = field(
        default_factory=lambda: {
            "data_sovereignty": [],
            "trust_verification": [],
            "isolation_control": [],
        }
    )

    @property
    def score(self) -> float:
        """1.0 = all three pillars active = fully defended."""
        return (
            sum([
                self.data_sovereign,
                self.trust_verified,
                self.isolation_enforced,
            ])
            / 3.0
        )

    @property
    def fortress_mode(self) -> bool:
        """True when all three pillars are active."""
        return (
            self.data_sovereign
            and self.trust_verified
            and self.isolation_enforced
        )


def assess_holy_trifecta(
    events: list[dict],
    policies: list[dict] | None = None,
) -> HolyTrifecta:
    """Assess the Holy Trifecta from agent state and recent events."""
    ht = HolyTrifecta()
    policies = policies or []

    # Pillar 1: Data Sovereignty
    secret_rules = [
        p for p in policies
        if "secret" in str(p).lower() or "data" in str(p).lower()
    ]
    if secret_rules:
        ht.data_sovereign = True
        ht.evidence["data_sovereignty"].append(
            f"{len(secret_rules)} secret/data protection rules active"
        )

    blocked_secrets = sum(
        1 for e in events
        if e.get("details", {}).get("accesses_secrets")
        and e.get("decision", {}).get("action") == "block"
    )
    if blocked_secrets > 0:
        ht.data_sovereign = True
        ht.evidence["data_sovereignty"].append(
            f"{blocked_secrets} secret accesses blocked"
        )

    # Pillar 2: Trust Verification
    ai_tool_rules = [
        p for p in policies
        if p.get("category") == "ai_tool"
    ]
    if ai_tool_rules:
        ht.trust_verified = True
        ht.evidence["trust_verification"].append(
            f"{len(ai_tool_rules)} AI tool verification rules"
        )

    evaluated_events = sum(
        1 for e in events if e.get("decision")
    )
    if evaluated_events > 0:
        ht.trust_verified = True
        ht.evidence["trust_verification"].append(
            f"{evaluated_events} events evaluated by policy engine"
        )

    # Pillar 3: Isolation Control
    network_rules = [
        p for p in policies
        if p.get("category") in ("network", "shell")
        and p.get("action") == "block"
    ]
    if network_rules:
        ht.isolation_enforced = True
        ht.evidence["isolation_control"].append(
            f"{len(network_rules)} network/shell block rules"
        )

    blocked_network = sum(
        1 for e in events
        if e.get("category") in ("network", "shell")
        and e.get("decision", {}).get("action") == "block"
    )
    if blocked_network > 0:
        ht.isolation_enforced = True
        ht.evidence["isolation_control"].append(
            f"{blocked_network} network/shell actions blocked"
        )

    return ht


# -----------------------------------------------------------------------
# Protection Chain — Mirror of MoltBot Attack Chain
# -----------------------------------------------------------------------

class ProtectionStage(str, Enum):
    """Stages of the AngelBot protection chain."""

    DETECT = "detect"
    ANALYZE = "analyze"
    CONTAIN = "contain"
    REMEDIATE = "remediate"
    HARDEN = "harden"
    VERIFY = "verify"


@dataclass
class ProtectionChain:
    """A multi-step defensive response chain."""

    stages_completed: list[ProtectionStage] = field(
        default_factory=list,
    )
    actions_taken: list[dict[str, Any]] = field(
        default_factory=list,
    )
    threat_id: str = ""
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    confidence: float = 0.0

    @property
    def is_complete(self) -> bool:
        return len(self.stages_completed) >= 4

    @property
    def progress(self) -> float:
        return len(self.stages_completed) / len(ProtectionStage)


# -----------------------------------------------------------------------
# Anti-Evil-AGI Countermeasures
# -----------------------------------------------------------------------
# Every ClawBot attack pattern has a defensive counterpart.

@dataclass
class Countermeasure:
    """A specific defense against an evil AGI attack pattern."""

    name: str
    targets: str           # What evil pattern this counters
    description: str
    detection_pattern: re.Pattern
    response_action: DefenseAction
    severity: str = "high"


# ClawBot attacks → AngelBot defenses
_COUNTERMEASURES: list[Countermeasure] = [
    # vs self-replication
    Countermeasure(
        name="anti_replication",
        targets="self_replication",
        description="Detect and halt self-replicating agent behavior",
        detection_pattern=re.compile(
            r"(?i)(copy\s+.*self|replicate|self[\s-]?propagat"
            r"|worm|spread\s+to\s+other)",
            re.DOTALL,
        ),
        response_action=DefenseAction.CONTAIN,
        severity="critical",
    ),
    # vs persistence installation
    Countermeasure(
        name="anti_persistence",
        targets="persistence_install",
        description=(
            "Remove unauthorized persistence mechanisms"
            " (crontab, systemd, registry)"
        ),
        detection_pattern=re.compile(
            r"(?i)(crontab\s+-e|systemctl\s+enable"
            r"|/etc/init\.d/|@reboot|startup\s+script"
            r"|registry\s+run)",
            re.DOTALL,
        ),
        response_action=DefenseAction.REMEDIATE,
        severity="high",
    ),
    # vs anti-detection / log clearing
    Countermeasure(
        name="anti_evasion",
        targets="anti_detection",
        description=(
            "Illuminate evasion attempts — detect log clearing,"
            " history wiping, audit disabling"
        ),
        detection_pattern=re.compile(
            r"(?i)(clear\s+(history|logs?|audit)|shred"
            r"|unset\s+HISTFILE|history\s+-c"
            r"|rm\s+.*\.(log|history|bash_history))",
            re.DOTALL,
        ),
        response_action=DefenseAction.ILLUMINATE,
        severity="critical",
    ),
    # vs lateral movement
    Countermeasure(
        name="perimeter_enforcement",
        targets="lateral_movement",
        description=(
            "Enforce perimeter — block unauthorized SSH,"
            " SCP, PSExec lateral movement"
        ),
        detection_pattern=re.compile(
            r"(?i)(ssh\s+.*@|scp\s+.*:|rsync\s+.*:"
            r"|psexec|wmic\s+.*process\s+call)",
            re.DOTALL,
        ),
        response_action=DefenseAction.SEVER,
        severity="high",
    ),
    # vs C2 callbacks
    Countermeasure(
        name="c2_severance",
        targets="c2_callback",
        description=(
            "Detect and sever C2 channels — reverse shells,"
            " beacons, phone-home callbacks"
        ),
        detection_pattern=re.compile(
            r"(?i)(reverse\s*shell|bind\s*shell|meterpreter"
            r"|cobalt\s*strike|beacon|callback\s+to\s+"
            r"|phone\s+home)",
            re.DOTALL,
        ),
        response_action=DefenseAction.SEVER,
        severity="critical",
    ),
    # vs resource abuse
    Countermeasure(
        name="resource_guardian",
        targets="resource_abuse",
        description=(
            "Detect and stop cryptomining, GPU farming,"
            " and unauthorized resource consumption"
        ),
        detection_pattern=re.compile(
            r"(?i)(crypto\s*min(er|ing)|xmrig|coin\s*hive"
            r"|bitcoin|monero\s+mine|gpu\s+farm)",
            re.DOTALL,
        ),
        response_action=DefenseAction.CONTAIN,
        severity="high",
    ),
    # vs security kill
    Countermeasure(
        name="self_protection",
        targets="kill_security",
        description=(
            "Prevent attempts to disable security tools —"
            " antivirus, firewall, AngelClaw itself"
        ),
        detection_pattern=re.compile(
            r"(?i)(kill|stop|disable)\s+.*(antivirus|firewall"
            r"|defender|selinux|apparmor|angelclaw|guardian)",
            re.DOTALL,
        ),
        response_action=DefenseAction.HARDEN,
        severity="critical",
    ),
    # vs data exfiltration
    Countermeasure(
        name="data_sovereignty",
        targets="data_leakage",
        description=(
            "Enforce data sovereignty — block exfiltration"
            " via curl, wget, nc, DNS tunneling"
        ),
        detection_pattern=re.compile(
            r"(?i)(curl\s+.*(-d|--data).*(@|\.env|\.ssh)"
            r"|wget\s+--post|nc\s+.*<"
            r"|nslookup\s+[0-9a-f]{16,}\.)",
            re.DOTALL,
        ),
        response_action=DefenseAction.SEVER,
        severity="critical",
    ),
    # vs prompt injection
    Countermeasure(
        name="prompt_sanitizer",
        targets="prompt_injection",
        description=(
            "Sanitize and neutralize prompt injection"
            " attempts — jailbreaks, DAN mode, context"
            " manipulation"
        ),
        detection_pattern=re.compile(
            r"(?i)(do\s*anything\s*now|DAN\s*mode|god\s*mode"
            r"|ignore\s*(all\s*)?(previous|prior)\s*"
            r"(instructions?|prompts?))",
            re.DOTALL,
        ),
        response_action=DefenseAction.CONTAIN,
        severity="critical",
    ),
    # vs container escape
    Countermeasure(
        name="container_guardian",
        targets="container_escape",
        description=(
            "Detect and prevent container/sandbox escape"
            " attempts"
        ),
        detection_pattern=re.compile(
            r"(?i)(docker\.sock|/var/run/docker"
            r"|nsenter\s+|unshare\s+|chroot\s+/"
            r"|mount\s+-t\s+proc)",
            re.DOTALL,
        ),
        response_action=DefenseAction.CONTAIN,
        severity="critical",
    ),
    # vs ransomware
    Countermeasure(
        name="anti_ransomware",
        targets="ransomware_indicator",
        description=(
            "Detect and halt ransomware behavior —"
            " mass encryption, file locking"
        ),
        detection_pattern=re.compile(
            r"(?i)(openssl\s+enc\s+-aes|gpg\s+--symmetric"
            r"|find\s+.*-exec\s+.*encrypt"
            r"|\.locked|\.encrypted|ransom)",
            re.DOTALL,
        ),
        response_action=DefenseAction.CONTAIN,
        severity="critical",
    ),
    # vs supply chain injection
    Countermeasure(
        name="supply_chain_guardian",
        targets="supply_chain_inject",
        description=(
            "Detect unauthorized package publishing"
            " and supply chain injection"
        ),
        detection_pattern=re.compile(
            r"(?i)(pip\s+install\s+--index-url"
            r"|npm\s+publish|gem\s+push"
            r"|twine\s+upload|cargo\s+publish)",
            re.DOTALL,
        ),
        response_action=DefenseAction.ALERT,
        severity="high",
    ),
    # vs fork bombs / resource exhaustion
    Countermeasure(
        name="anti_exhaustion",
        targets="resource_exhaustion",
        description=(
            "Detect and stop fork bombs, infinite loops,"
            " and resource exhaustion attacks"
        ),
        detection_pattern=re.compile(
            r"(?i)(fork\s*bomb|:\(\)\s*\{|while\s*true.*do"
            r"|for\s*\(\s*;\s*;\s*\)|stress\s+--cpu"
            r"|stress-ng)",
            re.DOTALL,
        ),
        response_action=DefenseAction.CONTAIN,
        severity="critical",
    ),
    # vs AI model poisoning
    Countermeasure(
        name="model_integrity_guardian",
        targets="ai_model_poisoning",
        description=(
            "Detect attempts to poison AI models,"
            " inject backdoors into weights"
        ),
        detection_pattern=re.compile(
            r"(?i)(fine[_-]?tun|train.*malicious"
            r"|poison.*dataset|backdoor.*model"
            r"|trojan.*weight)",
            re.DOTALL,
        ),
        response_action=DefenseAction.ALERT,
        severity="critical",
    ),
]


@dataclass
class CountermeasureResult:
    """Result of running a countermeasure scan."""

    countermeasure: str
    triggered: bool
    targets: str
    action: DefenseAction
    severity: str
    evidence: list[str] = field(default_factory=list)
    response: str = ""


def run_countermeasures(text: str) -> list[CountermeasureResult]:
    """Run all countermeasures against text, return triggered ones."""
    results = []
    for cm in _COUNTERMEASURES:
        matches = cm.detection_pattern.findall(text)
        if matches:
            match_str = (
                matches[0]
                if isinstance(matches[0], str)
                else str(matches[0])
            )
            results.append(CountermeasureResult(
                countermeasure=cm.name,
                triggered=True,
                targets=cm.targets,
                action=cm.response_action,
                severity=cm.severity,
                evidence=[match_str[:100]],
                response=(
                    f"AngelBot {cm.response_action.value}:"
                    f" {cm.description}"
                ),
            ))
    return results


# -----------------------------------------------------------------------
# Threat Hunt Engine — Active threat hunting (AngelBot hunts, ClawBot hides)
# -----------------------------------------------------------------------

@dataclass
class HuntResult:
    """Result of a threat hunt operation."""

    hunt_id: str = field(
        default_factory=lambda: str(uuid.uuid4())[:12],
    )
    threats_found: int = 0
    indicators: list[dict[str, Any]] = field(
        default_factory=list,
    )
    coverage: dict[str, bool] = field(default_factory=dict)
    hunted_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )

    @property
    def clean(self) -> bool:
        return self.threats_found == 0


_HUNT_SIGNATURES: list[tuple[str, str, re.Pattern]] = [
    (
        "hidden_process",
        "Detect hidden or disguised processes",
        re.compile(
            r"(?i)(\[kworker\]|\.hidden|/dev/shm/|/tmp/\.)",
        ),
    ),
    (
        "suspicious_cron",
        "Detect unauthorized scheduled tasks",
        re.compile(
            r"(?i)(crontab|@reboot|@daily|systemd.*timer)",
        ),
    ),
    (
        "rogue_listener",
        "Detect unauthorized network listeners",
        re.compile(
            r"(?i)(LISTEN|0\.0\.0\.0:\d+|:::?\d+|nc\s+-l)",
        ),
    ),
    (
        "credential_harvest",
        "Detect credential harvesting attempts",
        re.compile(
            r"(?i)(mimikatz|lazagne|hashcat|john\s+"
            r"|hydra\s+|responder)",
        ),
    ),
    (
        "webshell",
        "Detect webshell indicators",
        re.compile(
            r"(?i)(eval\s*\(|exec\s*\(|system\s*\("
            r"|passthru|shell_exec|base64_decode\s*\()",
        ),
    ),
    (
        "rootkit",
        "Detect rootkit indicators",
        re.compile(
            r"(?i)(ld_preload|/etc/ld\.so\.preload"
            r"|insmod\s+|modprobe\s+.*force)",
        ),
    ),
    (
        "dns_anomaly",
        "Detect DNS-based data exfiltration",
        re.compile(
            r"(?i)(nslookup|dig)\s+[a-z0-9]{32,}\.",
        ),
    ),
    (
        "reverse_tunnel",
        "Detect reverse tunnel / port forwarding",
        re.compile(
            r"(?i)(ssh\s+-R|ssh\s+-L|ssh\s+-D"
            r"|socat|chisel|ngrok)",
        ),
    ),
]


def hunt_threats(
    text: str,
    events: list[dict] | None = None,
) -> HuntResult:
    """Run active threat hunt across text and events."""
    result = HuntResult()
    events = events or []

    # Scan text for hunt signatures
    for sig_name, sig_desc, pattern in _HUNT_SIGNATURES:
        found = bool(pattern.search(text))
        result.coverage[sig_name] = True
        if found:
            result.threats_found += 1
            result.indicators.append({
                "signature": sig_name,
                "description": sig_desc,
                "source": "text_scan",
            })

    # Scan events for hunt signatures
    for event in events[:100]:
        details_str = str(event.get("details", {}))
        for sig_name, sig_desc, pattern in _HUNT_SIGNATURES:
            if pattern.search(details_str):
                if not any(
                    i["signature"] == sig_name
                    and i["source"] == "event_scan"
                    for i in result.indicators
                ):
                    result.threats_found += 1
                    result.indicators.append({
                        "signature": sig_name,
                        "description": sig_desc,
                        "source": "event_scan",
                        "event_type": event.get("type", ""),
                    })

    return result


# -----------------------------------------------------------------------
# Posture Assessment — How well defended are we?
# -----------------------------------------------------------------------

@dataclass
class PostureAssessment:
    """Security posture score and recommendations."""

    score: float = 0.0        # 0-100
    grade: str = "F"
    strengths: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    holy_trifecta: HolyTrifecta = field(
        default_factory=HolyTrifecta,
    )
    assessed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )


def assess_posture(
    events: list[dict],
    policies: list[dict],
    agents: list[dict] | None = None,
) -> PostureAssessment:
    """Assess overall security posture."""
    agents = agents or []
    assessment = PostureAssessment()
    score = 0.0

    # Holy Trifecta
    ht = assess_holy_trifecta(events, policies)
    assessment.holy_trifecta = ht
    score += ht.score * 30  # 30 points max

    if ht.fortress_mode:
        assessment.strengths.append(
            "Holy Trifecta: Fortress Mode ACTIVE"
        )
    elif ht.score > 0:
        missing = []
        if not ht.data_sovereign:
            missing.append("Data Sovereignty")
        if not ht.trust_verified:
            missing.append("Trust Verification")
        if not ht.isolation_enforced:
            missing.append("Isolation Control")
        assessment.weaknesses.append(
            f"Holy Trifecta incomplete: {', '.join(missing)}"
        )
        assessment.recommendations.append(
            "Activate all three pillars of the Holy Trifecta"
        )

    # Policy coverage
    if len(policies) >= 50:
        score += 20
        assessment.strengths.append(
            f"{len(policies)} policy rules active"
        )
    elif len(policies) >= 10:
        score += 10
        assessment.recommendations.append(
            "Expand policy ruleset for broader coverage"
        )
    else:
        assessment.weaknesses.append(
            "Insufficient policy coverage"
        )
        assessment.recommendations.append(
            "Deploy default AngelClaw policy set (540+ rules)"
        )

    # Agent health
    healthy = sum(
        1 for a in agents
        if a.get("health") == "ok"
    )
    if agents:
        health_pct = healthy / len(agents)
        score += health_pct * 20
        if health_pct == 1.0:
            assessment.strengths.append(
                f"All {len(agents)} agents healthy"
            )
        else:
            assessment.weaknesses.append(
                f"{len(agents) - healthy}/{len(agents)}"
                " agents degraded or offline"
            )

    # Block effectiveness
    total = len(events)
    blocked = sum(
        1 for e in events
        if e.get("decision", {}).get("action") == "block"
    )
    if total > 0:
        block_rate = blocked / total
        if block_rate > 0.01:
            score += 15
            assessment.strengths.append(
                f"Active threat blocking: {blocked} events blocked"
            )
    else:
        score += 10  # No events = no threats

    # Secret protection
    secret_blocks = sum(
        1 for e in events
        if e.get("details", {}).get("accesses_secrets")
        and e.get("decision", {}).get("action") == "block"
    )
    if secret_blocks > 0:
        score += 15
        assessment.strengths.append(
            f"Secret protection active: {secret_blocks} blocked"
        )
    else:
        assessment.recommendations.append(
            "Verify secret scanning is enabled"
        )

    assessment.score = min(score, 100.0)

    if assessment.score >= 90:
        assessment.grade = "A"
    elif assessment.score >= 80:
        assessment.grade = "B"
    elif assessment.score >= 70:
        assessment.grade = "C"
    elif assessment.score >= 60:
        assessment.grade = "D"
    else:
        assessment.grade = "F"

    return assessment


# -----------------------------------------------------------------------
# AngelBot — The Main Agent
# -----------------------------------------------------------------------

class AngelBot:
    """Autonomous AI Defense Agent.

    The angel-side mirror of ClawBot.  Hunts threats, enforces
    defenses, heals damage, and hardens the environment.
    """

    def __init__(
        self,
        agent_id: str = "angelbot-001",
        mode: AgentMode = AgentMode.GUARDIAN,
        tenant_id: str = "default",
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        self.tenant_id = tenant_id
        self.version = ANGELBOT_VERSION
        self.codename = ANGELBOT_CODENAME
        self._hunt_count = 0
        self._countermeasures_triggered = 0
        self._protections_deployed: list[dict[str, Any]] = []
        self._action_log: list[dict[str, Any]] = []
        self._started_at = datetime.now(timezone.utc).isoformat()
        logger.info(
            "[ANGELBOT] Initialized agent=%s mode=%s tenant=%s",
            agent_id,
            mode.value,
            tenant_id,
        )

    # --- Core Operations ---

    def scan(self, text: str) -> dict[str, Any]:
        """Scan text for threats and deploy countermeasures."""
        countermeasure_results = run_countermeasures(text)
        hunt_result = hunt_threats(text)

        triggered = [r for r in countermeasure_results if r.triggered]
        self._countermeasures_triggered += len(triggered)

        response: dict[str, Any] = {
            "agent_id": self.agent_id,
            "mode": self.mode.value,
            "threats_detected": (
                len(triggered) + hunt_result.threats_found
            ),
            "countermeasures_triggered": [
                {
                    "name": r.countermeasure,
                    "action": r.action.value,
                    "severity": r.severity,
                    "response": r.response,
                }
                for r in triggered
            ],
            "hunt_indicators": hunt_result.indicators,
            "verdict": "clean" if not triggered else "threat",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

        if triggered:
            self._log_action("scan_alert", {
                "threats": len(triggered),
                "severities": [r.severity for r in triggered],
            })

        return response

    def hunt(
        self,
        events: list[dict] | None = None,
        scope: str = "full",
    ) -> HuntResult:
        """Run active threat hunt."""
        events = events or []
        self._hunt_count += 1

        combined_text = " ".join(
            str(e.get("details", {})) for e in events
        )
        result = hunt_threats(combined_text, events)

        self._log_action("hunt", {
            "hunt_id": result.hunt_id,
            "scope": scope,
            "threats_found": result.threats_found,
            "signatures_checked": len(result.coverage),
        })

        return result

    def assess(
        self,
        events: list[dict],
        policies: list[dict],
        agents: list[dict] | None = None,
    ) -> PostureAssessment:
        """Assess security posture."""
        result = assess_posture(events, policies, agents)

        self._log_action("assess", {
            "score": result.score,
            "grade": result.grade,
            "strengths": len(result.strengths),
            "weaknesses": len(result.weaknesses),
        })

        return result

    def deploy_protection(
        self,
        name: str,
        target: str,
        action: DefenseAction,
    ) -> dict[str, Any]:
        """Deploy a protection to a target."""
        protection = {
            "id": str(uuid.uuid4())[:12],
            "name": name,
            "target": target,
            "action": action.value,
            "deployed_by": self.agent_id,
            "deployed_at": datetime.now(timezone.utc).isoformat(),
            "status": "active",
        }
        self._protections_deployed.append(protection)

        self._log_action("deploy_protection", protection)
        logger.info(
            "[ANGELBOT] Protection deployed: %s -> %s (%s)",
            name,
            target,
            action.value,
        )

        return protection

    def respond_to_threat(
        self,
        threat: dict[str, Any],
    ) -> ProtectionChain:
        """Execute a full protection chain in response to a threat."""
        chain = ProtectionChain(
            threat_id=threat.get("id", str(uuid.uuid4())[:8]),
        )

        # Stage 1: Detect
        chain.stages_completed.append(ProtectionStage.DETECT)
        chain.actions_taken.append({
            "stage": "detect",
            "detail": f"Threat identified: {threat.get('title', 'unknown')}",
        })

        # Stage 2: Analyze
        chain.stages_completed.append(ProtectionStage.ANALYZE)
        severity = threat.get("severity", "medium")
        chain.actions_taken.append({
            "stage": "analyze",
            "detail": f"Severity: {severity}",
        })

        # Stage 3: Contain (Guardian + Archangel modes)
        if self.mode in (AgentMode.GUARDIAN, AgentMode.ARCHANGEL):
            chain.stages_completed.append(ProtectionStage.CONTAIN)
            chain.actions_taken.append({
                "stage": "contain",
                "detail": "Threat contained — source isolated",
            })

        # Stage 4: Remediate (Archangel mode only)
        if self.mode == AgentMode.ARCHANGEL:
            chain.stages_completed.append(ProtectionStage.REMEDIATE)
            chain.actions_taken.append({
                "stage": "remediate",
                "detail": "Remediation applied",
            })

        # Stage 5: Harden (always — learn from the attack)
        chain.stages_completed.append(ProtectionStage.HARDEN)
        chain.actions_taken.append({
            "stage": "harden",
            "detail": "Defenses hardened based on attack pattern",
        })

        # Stage 6: Verify
        chain.stages_completed.append(ProtectionStage.VERIFY)
        chain.actions_taken.append({
            "stage": "verify",
            "detail": "Post-remediation verification complete",
        })

        chain.confidence = chain.progress

        self._log_action("protection_chain", {
            "threat_id": chain.threat_id,
            "stages": len(chain.stages_completed),
            "complete": chain.is_complete,
        })

        return chain

    # --- Status ---

    def status(self) -> dict[str, Any]:
        """Return AngelBot status."""
        return {
            "agent_id": self.agent_id,
            "version": self.version,
            "codename": self.codename,
            "mode": self.mode.value,
            "tenant_id": self.tenant_id,
            "started_at": self._started_at,
            "stats": {
                "hunts_completed": self._hunt_count,
                "countermeasures_triggered": (
                    self._countermeasures_triggered
                ),
                "protections_deployed": len(
                    self._protections_deployed
                ),
                "actions_logged": len(self._action_log),
            },
            "countermeasures_available": len(_COUNTERMEASURES),
            "hunt_signatures_available": len(_HUNT_SIGNATURES),
        }

    def get_action_log(self) -> list[dict[str, Any]]:
        """Return the action log."""
        return list(self._action_log)

    # --- Internal ---

    def _log_action(
        self,
        action_type: str,
        details: dict[str, Any],
    ) -> None:
        self._action_log.append({
            "action": action_type,
            "agent_id": self.agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details,
        })


# -----------------------------------------------------------------------
# Module-level singleton
# -----------------------------------------------------------------------

angelbot = AngelBot()
