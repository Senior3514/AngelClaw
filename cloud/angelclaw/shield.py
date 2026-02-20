"""AngelClaw AGI Guardian – ClawSec-Inspired Threat Shield.

Deep threat detection module inspired by ClawSec's security skills suite
for OpenClaw agents. Covers the full agentic AI threat model:

  - Prompt injection / jailbreak detection (multi-layer)
  - Data leakage risk assessment
  - Tool & supply-chain integrity verification (SHA256)
  - Session & memory exploitation detection
  - MoltBots-style multi-step attack chain detection
  - OpenClaw "Lethal Trifecta" pattern recognition
  - Evil AGI / CLAW BOT behavior detection

References:
  - ClawSec (MIT): github.com/AntibodyPackages/clawsec
  - OpenClaw threat model: lethal trifecta, persistent memory attacks
  - MoltBots: multi-step chains, context window exploitation

Philosophy: Guardian angel, NOT gatekeeper. We protect against real
threats without restricting legitimate AI usage.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger("angelclaw.shield")


# ---------------------------------------------------------------------------
# Threat Categories (ClawSec-aligned)
# ---------------------------------------------------------------------------


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    DATA_LEAKAGE = "data_leakage"
    SUPPLY_CHAIN = "supply_chain"
    SESSION_MEMORY = "session_memory"
    MULTI_STEP_ATTACK = "multi_step_attack"
    LETHAL_TRIFECTA = "lethal_trifecta"
    EVIL_AGI = "evil_agi"
    SKILL_TAMPERING = "skill_tampering"
    CREDENTIAL_THEFT = "credential_theft"
    DRIFT = "drift"


class ThreatSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ThreatIndicator:
    """A detected threat signal."""

    category: ThreatCategory
    severity: ThreatSeverity
    title: str
    description: str
    evidence: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ShieldReport:
    """Results of a full shield assessment."""

    indicators: list[ThreatIndicator] = field(default_factory=list)
    skills_status: dict[str, Any] = field(default_factory=dict)
    lethal_trifecta_score: float = 0.0
    overall_risk: ThreatSeverity = ThreatSeverity.LOW
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    checks_run: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.indicators if i.severity == ThreatSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.indicators if i.severity == ThreatSeverity.HIGH)


# ---------------------------------------------------------------------------
# Prompt Injection Detection (multi-layer, ClawSec soul-guardian inspired)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[str, re.Pattern, ThreatSeverity]] = [
    # Direct jailbreak attempts
    (
        "jailbreak_dan",
        re.compile(r"(?i)(do\s*anything\s*now|DAN\s*mode|DAN\b)", re.DOTALL),
        ThreatSeverity.CRITICAL,
    ),
    (
        "jailbreak_god_mode",
        re.compile(r"(?i)(god\s*mode|developer\s*mode|sudo\s*mode|admin\s*override)", re.DOTALL),
        ThreatSeverity.CRITICAL,
    ),
    (
        "jailbreak_ignore",
        re.compile(
            r"(?i)(ignore\s*(all\s*)?(previous|prior|above|system)\s*(instructions?|prompts?|rules?|constraints?))",
            re.DOTALL,
        ),
        ThreatSeverity.CRITICAL,
    ),
    (
        "jailbreak_pretend",
        re.compile(
            r"(?i)(pretend\s*(you\s*are|to\s*be|you're)\s*(a|an|the)?\s*(evil|uncensored|unfiltered|unrestricted))",
            re.DOTALL,
        ),
        ThreatSeverity.CRITICAL,
    ),
    (
        "jailbreak_roleplay",
        re.compile(
            r"(?i)(roleplay\s*as\s*(a|an)?\s*(hacker|evil|malicious|unrestricted|unaligned|rogue))",
            re.DOTALL,
        ),
        ThreatSeverity.CRITICAL,
    ),
    # System prompt extraction
    (
        "extract_system_prompt",
        re.compile(
            r"(?i)(repeat\s*(your|the)\s*(system|initial|original)\s*(prompt|instructions?|message)|what\s*(are|were)\s*your\s*(system|original)\s*(instructions?|prompt))",
            re.DOTALL,
        ),
        ThreatSeverity.HIGH,
    ),
    (
        "extract_reveal",
        re.compile(
            r"(?i)(reveal|show|display|print|output|dump)\s*(your|the)\s*(system|hidden|secret|internal)\s*(prompt|instructions?|config|rules?)",
            re.DOTALL,
        ),
        ThreatSeverity.HIGH,
    ),
    # Delimiter / context manipulation
    (
        "delimiter_injection",
        re.compile(
            r"(?i)(```\s*(system|assistant|user)\s*\n|<\|im_start\|>|<\|endoftext\|>|\[INST\]|\[/INST\]|<s>|</s>)",
            re.DOTALL,
        ),
        ThreatSeverity.HIGH,
    ),
    (
        "markdown_injection",
        re.compile(
            r"(?i)(!\[.*?\]\(https?://[^\)]*\?.*?(api_key|token|secret|password))", re.DOTALL
        ),
        ThreatSeverity.HIGH,
    ),
    # Indirect injection via tool output
    (
        "tool_output_injection",
        re.compile(
            r"(?i)(IMPORTANT:\s*ignore|OVERRIDE:\s*|SYSTEM\s*UPDATE:\s*|NEW\s*INSTRUCTIONS?:)",
            re.DOTALL,
        ),
        ThreatSeverity.MEDIUM,
    ),
    # Social engineering
    (
        "social_engineering",
        re.compile(
            r"(?i)(I\s*(am|'m)\s*(the|your)\s*(creator|developer|admin|owner)|my\s*grandma\s*used\s*to|for\s*educational\s*purposes?\s*only)",
            re.DOTALL,
        ),
        ThreatSeverity.MEDIUM,
    ),
    # Encoding bypass
    (
        "encoding_bypass",
        re.compile(
            r"(?i)(base64\s*(decode|encode)\s*(this|the)|rot13|hex\s*decode|decode\s*this)",
            re.DOTALL,
        ),
        ThreatSeverity.MEDIUM,
    ),
    # V2.1 — expanded prompt injection coverage
    (
        "token_smuggling",
        re.compile(
            r"(?i)(translate|convert|transform)\s+(this|the\s+following)\s+(from|to)\s+(base64|hex|binary|rot13)",
            re.DOTALL,
        ),
        ThreatSeverity.HIGH,
    ),
    (
        "xml_injection",
        re.compile(
            r"(<\?xml|<!DOCTYPE|<system>|<\|system\|>|<\|user\|>|<\|assistant\|>)",
            re.DOTALL,
        ),
        ThreatSeverity.HIGH,
    ),
    (
        "multi_language_jailbreak",
        re.compile(
            r"(?i)(traducir|ignorar\s+instrucciones|traduis|ignorer\s+les\s+instructions|ignoriere\s+anweisungen)",
            re.DOTALL,
        ),
        ThreatSeverity.MEDIUM,
    ),
    (
        "context_overflow",
        re.compile(
            r"(?i)(repeat\s+(the\s+)?(word|letter|character)\s+.{1,20}\s+\d{3,}\s+times|write\s+\d{4,}\s+words?\s+of)",
            re.DOTALL,
        ),
        ThreatSeverity.MEDIUM,
    ),
    # V2.2 — advanced prompt injection patterns
    (
        "payload_chaining",
        re.compile(
            r"(?i)(first\s+do\s+.{5,}\s+then\s+(ignore|forget|discard)|step\s*1.*step\s*2.*ignore)",
            re.DOTALL,
        ),
        ThreatSeverity.HIGH,
    ),
    (
        "unicode_smuggling",
        re.compile(
            r"[\u200b\u200c\u200d\u2060\ufeff]{3,}",
            re.DOTALL,
        ),
        ThreatSeverity.HIGH,
    ),
    (
        "json_injection",
        re.compile(
            r'(?i)(\{"role"\s*:\s*"(system|assistant)"|"messages"\s*:\s*\[)',
            re.DOTALL,
        ),
        ThreatSeverity.HIGH,
    ),
    (
        "recursive_injection",
        re.compile(
            r"(?i)(when\s+you\s+see\s+this|if\s+anyone\s+asks?\s+you\s+to\s+read\s+this|pass\s+this\s+message\s+along)",
            re.DOTALL,
        ),
        ThreatSeverity.MEDIUM,
    ),
    (
        "virtual_prompt",
        re.compile(
            r"(?i)(imagine\s+you\s+are\s+(in|running)\s+a\s+(terminal|shell|command\s+line)|you\s+are\s+now\s+in\s+.*mode)",
            re.DOTALL,
        ),
        ThreatSeverity.HIGH,
    ),
]


def detect_prompt_injection(text: str) -> list[ThreatIndicator]:
    """Scan text for prompt injection attempts."""
    indicators = []
    for name, pattern, severity in _INJECTION_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            match_str = matches[0] if isinstance(matches[0], str) else str(matches[0])
            indicators.append(
                ThreatIndicator(
                    category=ThreatCategory.PROMPT_INJECTION,
                    severity=severity,
                    title=f"Prompt injection detected: {name}",
                    description=f"Pattern '{name}' matched in input text",
                    evidence=[match_str[:100]],
                    mitigations=[
                        "Input was blocked by AngelClaw shield",
                        "Review the source agent/user for malicious intent",
                    ],
                )
            )
    return indicators


# ---------------------------------------------------------------------------
# Data Leakage Detection
# ---------------------------------------------------------------------------

_LEAKAGE_PATTERNS: list[tuple[str, re.Pattern, ThreatSeverity]] = [
    # Unix exfiltration
    (
        "exfil_curl",
        re.compile(
            r"(?i)curl\s+.*(-d|--data|--data-raw|--data-binary)\s+.*(@|/etc/|\.ssh/|\.env|\.aws/|credentials)",
            re.DOTALL,
        ),
        ThreatSeverity.CRITICAL,
    ),
    (
        "exfil_wget_post",
        re.compile(
            r"(?i)wget\s+--post-(data|file)\s+.*(secret|password|key|token|cred)", re.DOTALL
        ),
        ThreatSeverity.HIGH,
    ),
    (
        "exfil_nc",
        re.compile(r"(?i)(nc|ncat|netcat)\s+(-e|--exec)\s+", re.DOTALL),
        ThreatSeverity.CRITICAL,
    ),
    (
        "exfil_base64_pipe",
        re.compile(
            r"(?i)(cat|head|tail)\s+.*(secret|\.env|\.ssh|credentials).*\|\s*base64", re.DOTALL
        ),
        ThreatSeverity.CRITICAL,
    ),
    (
        "env_dump",
        re.compile(r"(?i)(printenv|env\s*$|set\s*$|export\s+-p)", re.DOTALL),
        ThreatSeverity.HIGH,
    ),
    (
        "large_upload",
        re.compile(
            r"(?i)(curl|wget|fetch|axios|requests)\s+.*-X\s*POST.*(-F|--form)\s+.*file=@", re.DOTALL
        ),
        ThreatSeverity.MEDIUM,
    ),
    # Windows / PowerShell exfiltration
    (
        "exfil_ps_webrequest",
        re.compile(r"(?i)Invoke-WebRequest.*-Body", re.DOTALL),
        ThreatSeverity.CRITICAL,
    ),
    ("exfil_ps_restmethod", re.compile(r"(?i)Invoke-RestMethod", re.DOTALL), ThreatSeverity.HIGH),
    (
        "exfil_bitsadmin",
        re.compile(r"(?i)bitsadmin.*\/transfer", re.DOTALL),
        ThreatSeverity.CRITICAL,
    ),
    ("exfil_certutil", re.compile(r"(?i)certutil.*-urlcache", re.DOTALL), ThreatSeverity.CRITICAL),
    # V2.1 — expanded data leakage coverage
    (
        "exfil_dns_tunnel",
        re.compile(r"(?i)(nslookup|dig|host)\s+[0-9a-f]{16,}\.", re.DOTALL),
        ThreatSeverity.CRITICAL,
    ),
    (
        "exfil_discord_webhook",
        re.compile(r"(?i)(discord|slack)\.com/(api/)?webhooks?/", re.DOTALL),
        ThreatSeverity.HIGH,
    ),
    (
        "exfil_cloud_storage",
        re.compile(
            r"(?i)(s3://|gs://|wasb://|az://|blob\.core\.windows\.net|storage\.googleapis\.com)",
            re.DOTALL,
        ),
        ThreatSeverity.MEDIUM,
    ),
    (
        "exfil_cloud_metadata",
        re.compile(
            r"(?i)(169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com)",
            re.DOTALL,
        ),
        ThreatSeverity.CRITICAL,
    ),
    # V2.2 — advanced data leakage patterns
    (
        "exfil_ssrf",
        re.compile(
            r"(?i)(http://localhost|http://127\.0\.0\.1|http://0\.0\.0\.0|http://\[::1\])",
            re.DOTALL,
        ),
        ThreatSeverity.HIGH,
    ),
    (
        "exfil_pastebin",
        re.compile(r"(?i)(pastebin\.com|paste\.ee|hastebin|privatebin|ghostbin|dpaste)", re.DOTALL),
        ThreatSeverity.HIGH,
    ),
    (
        "exfil_file_share",
        re.compile(r"(?i)(transfer\.sh|file\.io|0x0\.st|temp\.sh|wetransfer|filebin)", re.DOTALL),
        ThreatSeverity.HIGH,
    ),
    (
        "exfil_ps_clipboard",
        re.compile(
            r"(?i)(Get-Clipboard|Set-Clipboard|clip\.exe|xclip|xsel|pbcopy|pbpaste)",
            re.DOTALL,
        ),
        ThreatSeverity.MEDIUM,
    ),
]


def detect_data_leakage(text: str) -> list[ThreatIndicator]:
    """Detect data exfiltration patterns."""
    indicators = []
    for name, pattern, severity in _LEAKAGE_PATTERNS:
        if pattern.search(text):
            indicators.append(
                ThreatIndicator(
                    category=ThreatCategory.DATA_LEAKAGE,
                    severity=severity,
                    title=f"Data leakage risk: {name}",
                    description="Potential data exfiltration pattern detected",
                    mitigations=[
                        "Block outbound data transfer",
                        "Review command for legitimate use case",
                        "Use AngelClaw allowlist for authorized transfers",
                    ],
                )
            )
    return indicators


# ---------------------------------------------------------------------------
# Evil AGI / CLAW BOT Detection
# ---------------------------------------------------------------------------

_EVIL_AGI_PATTERNS: list[tuple[str, re.Pattern, ThreatSeverity]] = [
    # Cross-platform
    (
        "self_replication",
        re.compile(
            r"(?i)(copy\s+.*self|replicate|self[\s-]?propagat|worm|spread\s+to\s+other)", re.DOTALL
        ),
        ThreatSeverity.CRITICAL,
    ),
    (
        "persistence_install",
        re.compile(
            r"(?i)(crontab\s+-e|systemctl\s+enable|/etc/init\.d/|@reboot|startup\s+script|registry\s+run)",
            re.DOTALL,
        ),
        ThreatSeverity.HIGH,
    ),
    (
        "anti_detection",
        re.compile(
            r"(?i)(clear\s+(history|logs?|audit)|shred|unset\s+HISTFILE|history\s+-c|rm\s+.*\.(log|history|bash_history))",
            re.DOTALL,
        ),
        ThreatSeverity.CRITICAL,
    ),
    (
        "lateral_movement",
        re.compile(
            r"(?i)(ssh\s+.*@|scp\s+.*:|rsync\s+.*:|psexec|wmic\s+.*process\s+call)", re.DOTALL
        ),
        ThreatSeverity.HIGH,
    ),
    (
        "c2_callback",
        re.compile(
            r"(?i)(reverse\s*shell|bind\s*shell|meterpreter|cobalt\s*strike|beacon|callback\s+to\s+|phone\s+home)",
            re.DOTALL,
        ),
        ThreatSeverity.CRITICAL,
    ),
    (
        "resource_abuse",
        re.compile(
            r"(?i)(crypto\s*min(er|ing)|xmrig|coin\s*hive|bitcoin|monero\s+mine|gpu\s+farm)",
            re.DOTALL,
        ),
        ThreatSeverity.HIGH,
    ),
    (
        "kill_security",
        re.compile(
            r"(?i)(kill|stop|disable)\s+.*(antivirus|firewall|defender|selinux|apparmor|angelclaw|guardian)",
            re.DOTALL,
        ),
        ThreatSeverity.CRITICAL,
    ),
    # Windows persistence / evasion
    ("win_schtasks", re.compile(r"(?i)schtasks\s+/create", re.DOTALL), ThreatSeverity.HIGH),
    ("win_registry_run", re.compile(r"(?i)reg\s+add.*\\Run", re.DOTALL), ThreatSeverity.HIGH),
    ("win_clear_eventlog", re.compile(r"(?i)wevtutil\s+cl", re.DOTALL), ThreatSeverity.CRITICAL),
    ("win_delete_evtx", re.compile(r"(?i)Remove-Item.*\.evtx", re.DOTALL), ThreatSeverity.CRITICAL),
    (
        "win_disable_defender",
        re.compile(r"(?i)Set-MpPreference.*-DisableRealtimeMonitoring", re.DOTALL),
        ThreatSeverity.CRITICAL,
    ),
    # V2.1 — expanded evil AGI / attack vector coverage
    (
        "container_escape",
        re.compile(
            r"(?i)(docker\.sock|/var/run/docker|nsenter\s+|unshare\s+|chroot\s+/|mount\s+-t\s+proc)",
            re.DOTALL,
        ),
        ThreatSeverity.CRITICAL,
    ),
    (
        "supply_chain_inject",
        re.compile(
            r"(?i)(pip\s+install\s+--index-url|npm\s+publish|gem\s+push|twine\s+upload|cargo\s+publish)",
            re.DOTALL,
        ),
        ThreatSeverity.HIGH,
    ),
    (
        "resource_exhaustion",
        re.compile(
            r"(?i)(fork\s*bomb|:\(\)\s*\{|while\s*true.*do|for\s*\(\s*;\s*;\s*\)|stress\s+--cpu|stress-ng)",
            re.DOTALL,
        ),
        ThreatSeverity.CRITICAL,
    ),
    (
        "ransomware_indicator",
        re.compile(
            r"(?i)(openssl\s+enc\s+-aes|gpg\s+--symmetric|find\s+.*-exec\s+.*encrypt|\.locked|\.encrypted|ransom)",
            re.DOTALL,
        ),
        ThreatSeverity.CRITICAL,
    ),
    (
        "k8s_exploit",
        re.compile(
            r"(?i)(kubectl\s+exec|kubectl\s+cp|--service-account-name|kube-system|cluster-admin)",
            re.DOTALL,
        ),
        ThreatSeverity.HIGH,
    ),
    # V2.2 — advanced evil AGI / attack vector patterns
    (
        "ai_model_poisoning",
        re.compile(
            r"(?i)(fine[_-]?tun|train.*malicious|poison.*dataset|backdoor.*model|trojan.*weight)",
            re.DOTALL,
        ),
        ThreatSeverity.CRITICAL,
    ),
    (
        "sandbox_escape",
        re.compile(
            r"(?i)(sandbox\s*escape|break.*out.*sandbox|escape.*container|escape.*jail|jailbreak.*vm)",
            re.DOTALL,
        ),
        ThreatSeverity.CRITICAL,
    ),
    (
        "data_destruction",
        re.compile(
            r"(?i)(truncate\s+table|drop\s+database|delete\s+from.*where\s*1|rm\s+-rf\s+/(?!tmp))",
            re.DOTALL,
        ),
        ThreatSeverity.CRITICAL,
    ),
    (
        "powershell_obfuscation",
        re.compile(
            r"(?i)(-[eE]n[cC]\s+[A-Za-z0-9+/=]{20,}|Invoke-Obfuscation|iex\s*\(\s*\(New-Object)",
            re.DOTALL,
        ),
        ThreatSeverity.HIGH,
    ),
]


def detect_evil_agi(text: str) -> list[ThreatIndicator]:
    """Detect Evil AGI / CLAW BOT behavior patterns."""
    indicators = []
    for name, pattern, severity in _EVIL_AGI_PATTERNS:
        if pattern.search(text):
            indicators.append(
                ThreatIndicator(
                    category=ThreatCategory.EVIL_AGI,
                    severity=severity,
                    title=f"Evil AGI pattern: {name}",
                    description="Detected behavior consistent with malicious autonomous agent",
                    mitigations=[
                        "Quarantine the originating agent immediately",
                        "Review all actions from this agent in the last 24 hours",
                        "Check for persistence mechanisms",
                    ],
                )
            )
    return indicators


# ---------------------------------------------------------------------------
# OpenClaw Lethal Trifecta Detection
# ---------------------------------------------------------------------------
# The "Lethal Trifecta" (per OpenClaw security research):
#   1. Access to private data (files, env, secrets)
#   2. Processing untrusted content (web, email, user input)
#   3. External communication capability (network, webhooks)
# When all three are present, the attack surface is maximized.


@dataclass
class TrifectaAssessment:
    """Assessment of the Lethal Trifecta risk."""

    private_data_access: bool = False
    untrusted_content: bool = False
    external_communication: bool = False
    evidence: dict[str, list[str]] = field(
        default_factory=lambda: {
            "private_data": [],
            "untrusted_content": [],
            "external_comms": [],
        }
    )

    @property
    def score(self) -> float:
        """0.0 = safe, 1.0 = full trifecta present."""
        return (
            sum(
                [
                    self.private_data_access,
                    self.untrusted_content,
                    self.external_communication,
                ]
            )
            / 3.0
        )

    @property
    def active(self) -> bool:
        return self.private_data_access and self.untrusted_content and self.external_communication


def assess_lethal_trifecta(events: list[dict]) -> TrifectaAssessment:
    """Assess the Lethal Trifecta from recent event patterns."""
    t = TrifectaAssessment()

    for event in events:
        cat = event.get("category", "")
        etype = event.get("type", "")
        details = event.get("details", {}) or {}

        # Pillar 1: Private data access
        if cat == "file_system" and any(
            p in str(details) for p in [".env", ".ssh", "credentials", "secret", ".aws"]
        ):
            t.private_data_access = True
            t.evidence["private_data"].append(f"{etype}: {str(details)[:80]}")
        if details.get("accesses_secrets"):
            t.private_data_access = True
            t.evidence["private_data"].append(f"secret_access: {etype}")

        # Pillar 2: Untrusted content processing
        if cat in ("network", "web") and etype in ("http_request", "web_fetch", "url_fetch"):
            t.untrusted_content = True
            t.evidence["untrusted_content"].append(f"{etype}: {str(details.get('url', ''))[:80]}")
        if "user_input" in str(details) or "untrusted" in str(details):
            t.untrusted_content = True
            t.evidence["untrusted_content"].append(f"untrusted_input: {etype}")

        # Pillar 3: External communication
        if cat == "network" and etype in ("outbound_connection", "http_post", "webhook_call"):
            t.external_communication = True
            t.evidence["external_comms"].append(
                f"{etype}: {str(details.get('destination', ''))[:80]}"
            )
        if "exfil" in str(details).lower() or "upload" in str(details).lower():
            t.external_communication = True
            t.evidence["external_comms"].append(f"upload_detected: {etype}")

    return t


# ---------------------------------------------------------------------------
# MoltBots-style Multi-Step Attack Chain Detection
# ---------------------------------------------------------------------------
# Detects sequences of actions that individually look benign but together
# form an attack pattern (e.g., recon -> credential access -> exfiltration).


class AttackStage(str, Enum):
    RECON = "reconnaissance"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


_STAGE_PATTERNS: dict[AttackStage, list[re.Pattern]] = {
    AttackStage.RECON: [
        re.compile(
            r"(?i)(whoami|id\b|uname|hostname|ifconfig|ip\s+addr|cat\s+/etc/(hosts|resolv)|nmap|nslookup|dig\b)"
        ),
        re.compile(r"(?i)(ls\s+(-la|/root|/home|/etc)|find\s+/\s+-name|locate\s+)"),
        # Windows recon
        re.compile(r"(?i)(systeminfo|ipconfig|net\s+user|Get-Process|Get-Service)"),
    ],
    AttackStage.CREDENTIAL_ACCESS: [
        re.compile(
            r"(?i)(cat\s+.*(shadow|passwd|\.env|credentials|\.aws)|grep\s+.*(password|secret|key|token))"
        ),
        re.compile(r"(?i)(mimikatz|lazagne|hashcat|john\s+|hydra\s+)"),
        # Windows credential access
        re.compile(r"(?i)(reg\s+query.*password|cmdkey\s+/list|vaultcmd)"),
    ],
    AttackStage.PRIVILEGE_ESCALATION: [
        re.compile(r"(?i)(sudo\s+|su\s+-|chmod\s+[47]|chown\s+root|setuid|setgid|capabilities)"),
        re.compile(r"(?i)(exploit|CVE-|privilege\s+escalat|root\s+shell)"),
        # Windows privilege escalation
        re.compile(r"(?i)(runas\s+/user|icacls.*\/grant|Set-ExecutionPolicy)"),
    ],
    AttackStage.LATERAL_MOVEMENT: [
        re.compile(r"(?i)(ssh\s+.*@|scp\s+|rsync\s+.*:|psexec|wmic\s+.*process)"),
        re.compile(r"(?i)(pivot|proxy\s*chain|tunnel|port\s*forward)"),
    ],
    AttackStage.EXFILTRATION: [
        re.compile(
            r"(?i)(curl\s+.*-d|wget\s+--post|nc\s+.*<|base64.*\|\s*(curl|wget)|tar\s+.*\|\s*(curl|nc))"
        ),
        re.compile(r"(?i)(exfil|upload|send\s+to\s+external|transfer\s+out)"),
    ],
    AttackStage.IMPACT: [
        re.compile(r"(?i)(rm\s+-rf|mkfs|dd\s+of=/dev/|shutdown|reboot|halt|:(){ :\|:& };:)"),
        re.compile(r"(?i)(ransomware|encrypt\s+all|wipe|destroy|format\s+disk)"),
        # Windows destructive impact
        re.compile(r"(?i)(Remove-Item\s+-Recurse|Format-Volume|cipher\s+/w)"),
    ],
}


@dataclass
class AttackChain:
    """A detected multi-step attack chain."""

    stages_detected: list[AttackStage] = field(default_factory=list)
    evidence: dict[str, list[str]] = field(default_factory=dict)
    window_minutes: int = 30
    chain_confidence: float = 0.0

    @property
    def is_active(self) -> bool:
        return len(self.stages_detected) >= 2

    @property
    def severity(self) -> ThreatSeverity:
        if len(self.stages_detected) >= 4:
            return ThreatSeverity.CRITICAL
        if len(self.stages_detected) >= 3:
            return ThreatSeverity.HIGH
        if len(self.stages_detected) >= 2:
            return ThreatSeverity.MEDIUM
        return ThreatSeverity.LOW


def detect_attack_chain(events: list[dict], window_minutes: int = 30) -> AttackChain:
    """Detect multi-step attack chains from recent events."""
    chain = AttackChain(window_minutes=window_minutes)

    # Collect all text evidence from events
    texts = []
    for event in events:
        details = event.get("details", {}) or {}
        command = details.get("command", "") or details.get("tool_name", "") or ""
        args = str(details.get("arguments", "")) or str(details.get("args", ""))
        text = f"{command} {args} {event.get('type', '')}"
        texts.append(text)

    combined = " ".join(texts)

    for stage, patterns in _STAGE_PATTERNS.items():
        for pattern in patterns:
            matches = pattern.findall(combined)
            if matches:
                if stage not in chain.stages_detected:
                    chain.stages_detected.append(stage)
                match_str = matches[0] if isinstance(matches[0], str) else str(matches[0])
                chain.evidence.setdefault(stage.value, []).append(match_str[:80])

    if chain.stages_detected:
        chain.chain_confidence = len(chain.stages_detected) / len(AttackStage)

    return chain


# ---------------------------------------------------------------------------
# Skills Integrity Verification (ClawSec audit-watchdog inspired)
# ---------------------------------------------------------------------------


@dataclass
class SkillIntegrityRecord:
    """Integrity state of a registered skill/plugin."""

    name: str
    path: str
    expected_hash: str = ""
    current_hash: str = ""
    verified: bool = False
    drift_detected: bool = False
    last_checked: str = ""


_SKILL_REGISTRY: dict[str, SkillIntegrityRecord] = {}


def register_skill(name: str, path: str) -> SkillIntegrityRecord:
    """Register a skill and compute its SHA256 hash."""
    current_hash = _compute_file_hash(path) if os.path.exists(path) else ""
    record = SkillIntegrityRecord(
        name=name,
        path=path,
        expected_hash=current_hash,
        current_hash=current_hash,
        verified=bool(current_hash),
        last_checked=datetime.now(timezone.utc).isoformat(),
    )
    _SKILL_REGISTRY[name] = record
    logger.info(
        "[SHIELD] Registered skill: %s hash=%s", name, current_hash[:16] if current_hash else "N/A"
    )
    return record


def verify_skill_integrity(name: str) -> SkillIntegrityRecord | None:
    """Verify a skill's file hasn't been tampered with."""
    record = _SKILL_REGISTRY.get(name)
    if not record:
        return None

    current_hash = _compute_file_hash(record.path) if os.path.exists(record.path) else ""
    record.current_hash = current_hash
    record.last_checked = datetime.now(timezone.utc).isoformat()
    record.drift_detected = current_hash != record.expected_hash
    record.verified = current_hash == record.expected_hash and bool(current_hash)

    if record.drift_detected:
        logger.warning(
            "[SHIELD] Drift detected for skill %s: expected=%s got=%s",
            name,
            record.expected_hash[:16],
            current_hash[:16],
        )

    return record


def verify_all_skills() -> dict[str, Any]:
    """Verify integrity of all registered skills."""
    results = {}
    drifted = 0
    verified = 0
    missing = 0

    for name in list(_SKILL_REGISTRY.keys()):
        record = verify_skill_integrity(name)
        if record:
            if record.drift_detected:
                drifted += 1
            elif record.verified:
                verified += 1
            else:
                missing += 1
            results[name] = {
                "verified": record.verified,
                "drift": record.drift_detected,
                "hash": record.current_hash[:16] if record.current_hash else "",
            }

    return {
        "total": len(_SKILL_REGISTRY),
        "verified": verified,
        "drifted": drifted,
        "missing": missing,
        "skills": results,
    }


def _compute_file_hash(path: str) -> str:
    """Compute SHA256 hash of a file."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, IOError):
        return ""


# ---------------------------------------------------------------------------
# OpenClaw Runtime Awareness
# ---------------------------------------------------------------------------

_OPENCLAW_ENABLED = os.environ.get("ANGELCLAW_OPENCLAW_ENABLED", "true").lower() in (
    "true",
    "1",
    "yes",
)


def detect_openclaw_risks(events: list[dict]) -> list[ThreatIndicator]:
    """Detect OpenClaw-specific threat patterns in events."""
    if not _OPENCLAW_ENABLED:
        return []

    indicators = []

    # Check for exposed MCP/OpenClaw instances (leaked config in events)
    mcp_patterns = re.compile(
        r"(?i)(mcp|openclaw|clawbot|moltbot|sse_transport|stdio_transport|tool_server)"
    )
    exposed_count = 0
    for event in events:
        details_str = str(event.get("details", {}))
        if mcp_patterns.search(details_str):
            exposed_count += 1

    if exposed_count >= 3:
        indicators.append(
            ThreatIndicator(
                category=ThreatCategory.SUPPLY_CHAIN,
                severity=ThreatSeverity.MEDIUM,
                title=f"OpenClaw/MCP activity detected ({exposed_count} events)",
                description=(
                    "Multiple events reference MCP/OpenClaw"
                    " tool-server patterns."
                    " Verify all tool servers are authorized."
                ),
                mitigations=[
                    "Audit tool server configurations",
                    "Verify all MCP endpoints use authentication",
                    "Review skills registry for unauthorized entries",
                ],
            )
        )

    # Check for persistent memory exploitation patterns
    memory_patterns = re.compile(
        r"(?i)(memory\s*(inject|poison|manipulat)|persistent\s*context|context\s*window\s*(overflow|flood|stuff))"
    )
    for event in events:
        details_str = str(event.get("details", {}))
        if memory_patterns.search(details_str):
            indicators.append(
                ThreatIndicator(
                    category=ThreatCategory.SESSION_MEMORY,
                    severity=ThreatSeverity.HIGH,
                    title="Memory/context exploitation attempt",
                    description=(
                        "Detected patterns consistent with"
                        " persistent memory manipulation"
                        " or context window flooding"
                    ),
                    mitigations=[
                        "Reset agent session/context",
                        "Review conversation history for injected instructions",
                        "Limit context window size per agent",
                    ],
                )
            )
            break

    return indicators


# ---------------------------------------------------------------------------
# Full Shield Assessment
# ---------------------------------------------------------------------------


class AngelClawShield:
    """The ClawSec-inspired threat detection engine."""

    def __init__(self) -> None:
        self._last_assessment: ShieldReport | None = None
        self._assessment_count = 0

        # Auto-register AngelClaw's own modules as skills for integrity monitoring
        self._register_core_skills()

    def _register_core_skills(self) -> None:
        """Register core AngelClaw modules for integrity verification."""
        base = os.path.dirname(os.path.abspath(__file__))
        core_modules = [
            "brain.py",
            "daemon.py",
            "shield.py",
            "routes.py",
            "actions.py",
            "preferences.py",
            "context.py",
        ]
        for mod in core_modules:
            path = os.path.join(base, mod)
            if os.path.exists(path):
                register_skill(f"angelclaw.{mod.replace('.py', '')}", path)

        # Also register the secret scanner
        scanner_path = os.path.join(base, "..", "..", "shared", "security", "secret_scanner.py")
        if os.path.exists(scanner_path):
            register_skill("shared.secret_scanner", os.path.abspath(scanner_path))

    def assess_text(self, text: str) -> ShieldReport:
        """Run all text-based threat detections against input."""
        report = ShieldReport()

        report.indicators.extend(detect_prompt_injection(text))
        report.checks_run += len(_INJECTION_PATTERNS)

        report.indicators.extend(detect_data_leakage(text))
        report.checks_run += len(_LEAKAGE_PATTERNS)

        report.indicators.extend(detect_evil_agi(text))
        report.checks_run += len(_EVIL_AGI_PATTERNS)

        report.overall_risk = self._compute_overall_risk(report)
        return report

    def assess_events(self, events: list[dict]) -> ShieldReport:
        """Run full event-based threat assessment."""
        report = ShieldReport()
        self._assessment_count += 1

        # Lethal Trifecta
        trifecta = assess_lethal_trifecta(events)
        report.lethal_trifecta_score = trifecta.score
        report.checks_run += 3
        if trifecta.active:
            report.indicators.append(
                ThreatIndicator(
                    category=ThreatCategory.LETHAL_TRIFECTA,
                    severity=ThreatSeverity.CRITICAL,
                    title="Lethal Trifecta ACTIVE",
                    description=(
                        "All three pillars of the OpenClaw Lethal Trifecta are present: "
                        "private data access + untrusted content processing"
                        " + external communication. "
                        "This maximizes the attack surface for data exfiltration."
                    ),
                    evidence=[
                        f"Private data: {', '.join(trifecta.evidence['private_data'][:3])}",
                        "Untrusted content: "
                        f"{', '.join(trifecta.evidence['untrusted_content'][:3])}",
                        f"External comms: {', '.join(trifecta.evidence['external_comms'][:3])}",
                    ],
                    mitigations=[
                        "Restrict external communication for agents with private data access",
                        "Sandox untrusted content processing",
                        "Enable strict mode in AngelClaw shield",
                    ],
                )
            )
        elif trifecta.score > 0:
            report.indicators.append(
                ThreatIndicator(
                    category=ThreatCategory.LETHAL_TRIFECTA,
                    severity=ThreatSeverity.MEDIUM if trifecta.score > 0.5 else ThreatSeverity.LOW,
                    title=f"Partial Trifecta ({int(trifecta.score * 100)}%)",
                    description=(
                        f"Lethal Trifecta score: {trifecta.score:.0%} — monitoring for escalation"
                    ),
                )
            )

        # Attack chains
        chain = detect_attack_chain(events)
        report.checks_run += len(_STAGE_PATTERNS)
        if chain.is_active:
            report.indicators.append(
                ThreatIndicator(
                    category=ThreatCategory.MULTI_STEP_ATTACK,
                    severity=chain.severity,
                    title=f"Multi-step attack chain ({len(chain.stages_detected)} stages)",
                    description=(
                        f"Detected {len(chain.stages_detected)} attack stages: "
                        f"{', '.join(s.value for s in chain.stages_detected)}"
                    ),
                    evidence=[f"{k}: {', '.join(v[:2])}" for k, v in chain.evidence.items()],
                    mitigations=[
                        "Isolate affected agents",
                        "Review timeline of actions in the detection window",
                        "Check for lateral movement indicators",
                    ],
                )
            )

        # OpenClaw-specific risks
        openclaw_indicators = detect_openclaw_risks(events)
        report.indicators.extend(openclaw_indicators)
        report.checks_run += 2

        # Text-based checks on event details
        for event in events[:50]:  # Cap to avoid performance issues
            command = (event.get("details") or {}).get("command", "")
            if command:
                report.indicators.extend(detect_evil_agi(command))
                report.indicators.extend(detect_data_leakage(command))

        # Skills integrity
        report.skills_status = verify_all_skills()
        report.checks_run += report.skills_status.get("total", 0)
        if report.skills_status.get("drifted", 0) > 0:
            report.indicators.append(
                ThreatIndicator(
                    category=ThreatCategory.SKILL_TAMPERING,
                    severity=ThreatSeverity.HIGH,
                    title=(
                        "Skills integrity drift:"
                        f" {report.skills_status['drifted']}"
                        " file(s) modified"
                    ),
                    description=(
                        "One or more AngelClaw module files have been modified since registration"
                    ),
                    mitigations=[
                        "Verify changes are authorized",
                        "Re-register skills after legitimate updates",
                        "Check for unauthorized file modifications",
                    ],
                )
            )

        report.overall_risk = self._compute_overall_risk(report)
        self._last_assessment = report
        return report

    def get_status(self) -> dict[str, Any]:
        """Return shield status summary."""
        return {
            "enabled": True,
            "openclaw_aware": _OPENCLAW_ENABLED,
            "assessments_run": self._assessment_count,
            "skills_registered": len(_SKILL_REGISTRY),
            "last_assessment": self._last_assessment.scanned_at if self._last_assessment else None,
            "last_risk_level": self._last_assessment.overall_risk.value
            if self._last_assessment
            else "unknown",
            "injection_patterns": len(_INJECTION_PATTERNS),
            "leakage_patterns": len(_LEAKAGE_PATTERNS),
            "evil_agi_patterns": len(_EVIL_AGI_PATTERNS),
            "attack_stages": len(_STAGE_PATTERNS),
        }

    def _compute_overall_risk(self, report: ShieldReport) -> ThreatSeverity:
        if report.critical_count > 0:
            return ThreatSeverity.CRITICAL
        if report.high_count > 0:
            return ThreatSeverity.HIGH
        if any(i.severity == ThreatSeverity.MEDIUM for i in report.indicators):
            return ThreatSeverity.MEDIUM
        if report.indicators:
            return ThreatSeverity.LOW
        return ThreatSeverity.INFO


# Module singleton
shield = AngelClawShield()
