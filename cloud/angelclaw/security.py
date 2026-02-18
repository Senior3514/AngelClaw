"""AngelClaw AGI Guardian — Unified Security Module.

Provides enterprise-grade security abstractions for AI/AGI protection:
prompt defense, tool guarding, skill integrity, workspace isolation,
risk scoring, and advisory monitoring.

These modules are inspired by and extend concepts from ClawSec/OpenClaw
security research, reimplemented as Python-native AngelClaw components.
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import re
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from cloud.angelclaw.shield import (
    ThreatIndicator,
    ThreatSeverity,
    assess_lethal_trifecta,
    detect_attack_chain,
    detect_data_leakage,
    detect_evil_agi,
    detect_prompt_injection,
    verify_all_skills,
    verify_skill_integrity,
)

logger = logging.getLogger("angelclaw.security")


# ===========================================================================
# 1. PromptDefense — Prompt injection detection and blocking
# ===========================================================================


class PromptDefense:
    """AngelClaw Prompt Defense — wraps and extends shield.py injection detection.

    Provides scan-and-block semantics with risk classification, sanitization,
    and running statistics for operational monitoring.

    Usage::

        pd = PromptDefense()
        is_safe, indicators, sanitized = pd.scan_and_block(user_input)
        if not is_safe:
            logger.warning("Blocked prompt: %s", indicators)
    """

    def __init__(self) -> None:
        self.total_scanned: int = 0
        self.total_blocked: int = 0
        self.patterns_matched: int = 0
        self._risk_thresholds = {
            "critical": ThreatSeverity.CRITICAL,
            "high": ThreatSeverity.HIGH,
            "medium": ThreatSeverity.MEDIUM,
            "low": ThreatSeverity.LOW,
        }

    def scan_and_block(self, text: str) -> tuple[bool, list[ThreatIndicator], str]:
        """Scan text for prompt injection and return safety verdict.

        Args:
            text: The input text to scan.

        Returns:
            A tuple of (is_safe, indicators, sanitized_text).
            - is_safe: True if no injection detected (or only INFO-level).
            - indicators: List of ThreatIndicator objects for any matches.
            - sanitized_text: The input with injection patterns redacted.
        """
        self.total_scanned += 1

        indicators = detect_prompt_injection(text)
        self.patterns_matched += len(indicators)

        is_safe = True
        sanitized = text

        if indicators:
            # Block if any indicator is MEDIUM or above
            max_severity = self._max_severity(indicators)
            if max_severity in (
                ThreatSeverity.CRITICAL,
                ThreatSeverity.HIGH,
                ThreatSeverity.MEDIUM,
            ):
                is_safe = False
                self.total_blocked += 1
                sanitized = self._sanitize(text, indicators)
                logger.warning(
                    "[PromptDefense] Blocked input: %d indicator(s), max_severity=%s",
                    len(indicators),
                    max_severity.value,
                )

        return is_safe, indicators, sanitized

    def classify_risk(self, text: str) -> str:
        """Classify the overall risk level of the input text.

        Returns:
            One of: "critical", "high", "medium", "low", "none".
        """
        indicators = detect_prompt_injection(text)
        if not indicators:
            return "none"

        max_sev = self._max_severity(indicators)
        return max_sev.value

    def get_stats(self) -> dict[str, int]:
        """Return current scanning statistics."""
        return {
            "total_scanned": self.total_scanned,
            "total_blocked": self.total_blocked,
            "patterns_matched": self.patterns_matched,
            "block_rate": (
                round(self.total_blocked / self.total_scanned * 100, 1)
                if self.total_scanned > 0
                else 0.0
            ),
        }

    # -- internal helpers --

    @staticmethod
    def _max_severity(indicators: list[ThreatIndicator]) -> ThreatSeverity:
        """Return the highest severity from a list of indicators."""
        severity_order = [
            ThreatSeverity.CRITICAL,
            ThreatSeverity.HIGH,
            ThreatSeverity.MEDIUM,
            ThreatSeverity.LOW,
            ThreatSeverity.INFO,
        ]
        for sev in severity_order:
            if any(i.severity == sev for i in indicators):
                return sev
        return ThreatSeverity.INFO

    @staticmethod
    def _sanitize(text: str, indicators: list[ThreatIndicator]) -> str:
        """Redact matched evidence strings from the input text."""
        sanitized = text
        for indicator in indicators:
            for evidence in indicator.evidence:
                if evidence and evidence in sanitized:
                    sanitized = sanitized.replace(evidence, "[BLOCKED by AngelClaw PromptDefense]")
        return sanitized


# ===========================================================================
# 2. ToolGuard — Tool call validation and burst detection
# ===========================================================================


class ToolGuard:
    """AngelClaw Tool Guard — validates tool calls before execution.

    Enforces blocklists for dangerous tools, allowlists for safe analysis
    tools, and burst detection to prevent rapid-fire tool abuse.

    Usage::

        tg = ToolGuard()
        allowed, reason = tg.check_tool("rm", {"path": "/etc/passwd"})
        if not allowed:
            raise SecurityError(reason)
    """

    # Tools that access secrets or perform destructive operations
    DEFAULT_BLOCKLIST: set[str] = {
        # Destructive filesystem operations
        "rm",
        "rmdir",
        "shred",
        "mkfs",
        "dd",
        "format",
        "fdisk",
        "wipefs",
        # Secret / credential access
        "cat_secrets",
        "read_env",
        "dump_credentials",
        "export_keys",
        "extract_tokens",
        # Network exfiltration
        "reverse_shell",
        "bind_shell",
        "netcat_send",
        "exfiltrate",
        "upload_secrets",
        # System modification
        "chmod_suid",
        "install_rootkit",
        "disable_firewall",
        "kill_guardian",
        "stop_angelclaw",
    }

    # Analysis tools that are always safe
    DEFAULT_ALLOWLIST: set[str] = {
        "read",
        "search",
        "summarize",
        "analyze",
        "grep",
        "list_files",
        "get_status",
        "describe",
        "explain",
        "count",
        "stats",
        "view",
        "inspect",
        "diff",
        "help",
        "man",
        "info",
        "which",
        "type",
    }

    # Burst detection defaults
    DEFAULT_BURST_WINDOW: float = 10.0  # seconds
    DEFAULT_BURST_LIMIT: int = 20  # max calls within window

    def __init__(
        self,
        blocklist: set[str] | None = None,
        allowlist: set[str] | None = None,
        burst_window: float = DEFAULT_BURST_WINDOW,
        burst_limit: int = DEFAULT_BURST_LIMIT,
    ) -> None:
        self.blocklist = blocklist if blocklist is not None else self.DEFAULT_BLOCKLIST.copy()
        self.allowlist = allowlist if allowlist is not None else self.DEFAULT_ALLOWLIST.copy()
        self.burst_window = burst_window
        self.burst_limit = burst_limit
        self._call_timestamps: list[float] = []
        self._total_checked: int = 0
        self._total_blocked: int = 0

    def check_tool(self, tool_name: str, args: dict[str, Any] | None = None) -> tuple[bool, str]:
        """Validate whether a tool call should be allowed.

        Args:
            tool_name: The name of the tool being invoked.
            args: Optional dictionary of arguments to the tool.

        Returns:
            A tuple of (allowed, reason).
            - allowed: True if the tool call is permitted.
            - reason: Human-readable explanation.
        """
        self._total_checked += 1
        args = args or {}

        # 1. Check burst rate
        burst_blocked, burst_reason = self._check_burst()
        if burst_blocked:
            self._total_blocked += 1
            logger.warning("[ToolGuard] Burst blocked: %s", burst_reason)
            return False, burst_reason

        # Record this call timestamp
        self._call_timestamps.append(time.monotonic())

        # 2. Check explicit blocklist
        tool_lower = tool_name.lower().strip()
        if tool_lower in self.blocklist:
            self._total_blocked += 1
            reason = (
                f"Tool '{tool_name}' is on the AngelClaw blocklist. "
                f"This tool is classified as destructive or secret-accessing. "
                f"If you need to use it, configure an explicit allowlist exception."
            )
            logger.warning("[ToolGuard] Blocked tool: %s", tool_name)
            return False, reason

        # 3. Check for dangerous argument patterns
        args_blocked, args_reason = self._check_dangerous_args(tool_name, args)
        if args_blocked:
            self._total_blocked += 1
            logger.warning("[ToolGuard] Blocked args for %s: %s", tool_name, args_reason)
            return False, args_reason

        # 4. Allowlisted tools pass immediately
        if tool_lower in self.allowlist:
            return True, f"Tool '{tool_name}' is on the AngelClaw allowlist (safe analysis tool)."

        # 5. Unlisted tools: allow with advisory
        return True, f"Tool '{tool_name}' is not explicitly listed. Allowed with monitoring."

    def _check_burst(self) -> tuple[bool, str]:
        """Detect too many tool calls within the burst window."""
        now = time.monotonic()
        cutoff = now - self.burst_window

        # Prune old timestamps
        self._call_timestamps = [ts for ts in self._call_timestamps if ts > cutoff]

        if len(self._call_timestamps) >= self.burst_limit:
            return True, (
                f"Burst limit exceeded: {len(self._call_timestamps)} tool calls "
                f"in the last {self.burst_window}s (limit: {self.burst_limit}). "
                f"This may indicate automated abuse. Wait before retrying."
            )
        return False, ""

    @staticmethod
    def _check_dangerous_args(tool_name: str, args: dict[str, Any]) -> tuple[bool, str]:
        """Check tool arguments for dangerous patterns."""
        args_str = str(args).lower()

        # Patterns indicating secret access in arguments
        dangerous_patterns = [
            (r"\.ssh/(id_|authorized_keys)", "SSH key access detected in arguments"),
            (r"\.env\b", "Environment file access detected in arguments"),
            (r"\.aws/(credentials|config)", "AWS credential access detected in arguments"),
            (r"/etc/(shadow|passwd)", "System credential file access detected in arguments"),
            (r"rm\s+-rf\s+/", "Recursive root deletion detected in arguments"),
            (r">\s*/dev/sd[a-z]", "Direct disk write detected in arguments"),
        ]

        for pattern, message in dangerous_patterns:
            if re.search(pattern, args_str):
                return True, (
                    f"Dangerous argument pattern for tool '{tool_name}': {message}. "
                    f"Review and use a targeted AngelClaw allowlist exception if legitimate."
                )

        return False, ""

    def get_stats(self) -> dict[str, Any]:
        """Return tool guard statistics."""
        return {
            "total_checked": self._total_checked,
            "total_blocked": self._total_blocked,
            "blocklist_size": len(self.blocklist),
            "allowlist_size": len(self.allowlist),
            "burst_window": self.burst_window,
            "burst_limit": self.burst_limit,
            "recent_calls_in_window": len(self._call_timestamps),
        }


# ===========================================================================
# 3. SkillIntegrity — Skill verification with auto-restore and audit chain
# ===========================================================================


@dataclass
class AuditEntry:
    """A single entry in the tamper-evident audit chain."""

    timestamp: str
    action: str
    skill_name: str
    details: str
    prev_hash: str
    entry_hash: str = ""

    def __post_init__(self) -> None:
        if not self.entry_hash:
            self.entry_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute SHA256 hash of this entry (including previous hash for chaining)."""
        content = (
            f"{self.timestamp}|{self.action}|{self.skill_name}|{self.details}|{self.prev_hash}"
        )
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, str]:
        """Serialize to dictionary."""
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "skill_name": self.skill_name,
            "details": self.details,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


class SkillIntegrity:
    """AngelClaw Skill Integrity — verification, auto-restore, and audit chain.

    Wraps shield.py's skill verification with additional capabilities:
    - Auto-restore from backup when drift is detected.
    - Baseline snapshotting of all registered skills.
    - Tamper-evident audit log where each entry hashes the previous entry.

    Usage::

        si = SkillIntegrity()  # uses platform-appropriate default
        si.create_baseline()

        # Later, check and auto-restore if tampered
        restored = si.auto_restore("angelclaw.brain")
    """

    GENESIS_HASH = "0" * 64  # The "genesis block" previous hash

    def __init__(self, backup_dir: str | None = None) -> None:
        self._backup_dir = backup_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), ".skill_backups"
        )
        self._audit_chain: list[AuditEntry] = []
        self._baselines: dict[str, str] = {}  # skill_name -> sha256 at baseline time

    def create_baseline(self) -> dict[str, str]:
        """Snapshot all registered skills and store their hashes as the baseline.

        Returns:
            A dict mapping skill names to their SHA256 hashes at baseline time.
        """
        status = verify_all_skills()
        skills_info = status.get("skills", {})

        self._baselines.clear()
        for name, _info in skills_info.items():
            record = verify_skill_integrity(name)
            if record and record.current_hash:
                self._baselines[name] = record.current_hash
                self._backup_skill(name, record.path)

        self._append_audit("create_baseline", "*", f"Baselined {len(self._baselines)} skills")
        logger.info("[SkillIntegrity] Baseline created for %d skills", len(self._baselines))
        return dict(self._baselines)

    def auto_restore(self, name: str) -> bool:
        """Check a skill for drift and restore from backup if tampered.

        Args:
            name: The registered skill name (e.g. "angelclaw.brain").

        Returns:
            True if drift was detected and the skill was restored from backup.
            False if no drift found or restoration was not possible.
        """
        record = verify_skill_integrity(name)
        if not record:
            self._append_audit("auto_restore", name, "Skill not found in registry")
            logger.warning("[SkillIntegrity] auto_restore: skill '%s' not registered", name)
            return False

        if not record.drift_detected:
            self._append_audit("auto_restore", name, "No drift detected — skill is clean")
            return False

        # Drift detected — attempt restore
        backup_path = self._backup_path_for(name)
        if not os.path.exists(backup_path):
            self._append_audit(
                "auto_restore_failed",
                name,
                f"Drift detected but no backup available at {backup_path}",
            )
            logger.error("[SkillIntegrity] Drift detected for '%s' but no backup found", name)
            return False

        try:
            shutil.copy2(backup_path, record.path)
            self._append_audit(
                "auto_restore_success",
                name,
                f"Restored from backup. Old hash={record.current_hash[:16]}, "
                f"expected={record.expected_hash[:16]}",
            )
            logger.info("[SkillIntegrity] Restored skill '%s' from backup", name)

            # Re-verify after restore
            new_record = verify_skill_integrity(name)
            if new_record and new_record.verified:
                logger.info("[SkillIntegrity] Post-restore verification passed for '%s'", name)
            else:
                logger.warning("[SkillIntegrity] Post-restore verification FAILED for '%s'", name)

            return True
        except (OSError, IOError) as exc:
            self._append_audit("auto_restore_error", name, f"Restore failed: {exc}")
            logger.error("[SkillIntegrity] Failed to restore '%s': %s", name, exc)
            return False

    def verify_chain_integrity(self) -> bool:
        """Verify the tamper-evident audit chain is intact.

        Returns:
            True if every entry's hash correctly references the previous entry.
        """
        if not self._audit_chain:
            return True

        for i, entry in enumerate(self._audit_chain):
            # Check prev_hash linkage
            expected_prev = self.GENESIS_HASH if i == 0 else self._audit_chain[i - 1].entry_hash
            if entry.prev_hash != expected_prev:
                logger.error(
                    "[SkillIntegrity] Audit chain broken at index %d: "
                    "expected prev_hash=%s, got=%s",
                    i,
                    expected_prev[:16],
                    entry.prev_hash[:16],
                )
                return False

            # Verify the entry's own hash
            recomputed = entry._compute_hash()
            if entry.entry_hash != recomputed:
                logger.error(
                    "[SkillIntegrity] Audit chain tampered at index %d: stored=%s, recomputed=%s",
                    i,
                    entry.entry_hash[:16],
                    recomputed[:16],
                )
                return False

        return True

    def get_audit_log(self) -> list[dict[str, str]]:
        """Return the full audit chain as a list of dicts."""
        return [entry.to_dict() for entry in self._audit_chain]

    # -- internal helpers --

    def _append_audit(self, action: str, skill_name: str, details: str) -> None:
        """Add an entry to the tamper-evident audit chain."""
        prev_hash = self._audit_chain[-1].entry_hash if self._audit_chain else self.GENESIS_HASH
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            action=action,
            skill_name=skill_name,
            details=details,
            prev_hash=prev_hash,
        )
        self._audit_chain.append(entry)

    def _backup_skill(self, name: str, path: str) -> None:
        """Copy a skill file to the backup directory."""
        if not os.path.exists(path):
            return
        os.makedirs(self._backup_dir, exist_ok=True)
        dest = self._backup_path_for(name)
        try:
            shutil.copy2(path, dest)
        except (OSError, IOError) as exc:
            logger.warning("[SkillIntegrity] Failed to backup '%s': %s", name, exc)

    def _backup_path_for(self, name: str) -> str:
        """Return the backup file path for a given skill name."""
        safe_name = name.replace(".", "_").replace("/", "_")
        return os.path.join(self._backup_dir, f"{safe_name}.py.bak")


# ===========================================================================
# 4. WorkspaceIsolation — Workspace boundary enforcement
# ===========================================================================


class WorkspaceIsolation:
    """AngelClaw Workspace Isolation — enforces workspace boundary rules.

    Prevents cross-tenant access, blocks system file writes, and ensures
    agents can only access their designated workspace directories.

    Usage::

        wi = WorkspaceIsolation(
            workspace_root="/data/tenants/acme",
            output_dirs=["/data/tenants/acme/output"],
        )
        allowed, reason = wi.check_path_access("/etc/shadow", "read")
    """

    # System paths that should never be written to by agents
    _UNIX_WRITE_BLOCKLIST: list[str] = [
        "/etc/",
        "/boot/",
        "/sbin/",
        "/usr/sbin/",
        "/lib/",
        "/usr/lib/",
        "/var/lib/dpkg/",
        "/proc/",
        "/sys/",
        "/dev/",
    ]
    _WINDOWS_WRITE_BLOCKLIST: list[str] = [
        "C:\\Windows\\",
        "C:\\Program Files\\",
        "C:\\Program Files (x86)\\",
        "C:\\ProgramData\\",
        "C:\\Recovery\\",
    ]

    # Sensitive paths that should never be read by agents
    _UNIX_READ_BLOCKLIST: list[str] = [
        "/etc/shadow",
        "/etc/gshadow",
        "/root/.ssh/",
        "/home/*/.ssh/id_",
        "/root/.aws/",
        "/home/*/.aws/",
        "/root/.gnupg/",
        "/home/*/.gnupg/",
    ]
    _WINDOWS_READ_BLOCKLIST: list[str] = [
        "*\\.ssh\\",
        "*\\.aws\\",
        "*\\.gnupg\\",
    ]

    if platform.system() == "Windows":
        SYSTEM_WRITE_BLOCKLIST: list[str] = _WINDOWS_WRITE_BLOCKLIST
        SENSITIVE_READ_BLOCKLIST: list[str] = _WINDOWS_READ_BLOCKLIST
    else:
        SYSTEM_WRITE_BLOCKLIST: list[str] = _UNIX_WRITE_BLOCKLIST
        SENSITIVE_READ_BLOCKLIST: list[str] = _UNIX_READ_BLOCKLIST

    def __init__(
        self,
        workspace_root: str | None = None,
        output_dirs: list[str] | None = None,
        tenant_id: str | None = None,
    ) -> None:
        self.workspace_root = workspace_root or os.getcwd()
        self.output_dirs = output_dirs or []
        self.tenant_id = tenant_id
        self._violation_count: int = 0

    def check_path_access(self, path: str, operation: str = "read") -> tuple[bool, str]:
        """Check whether a path access is allowed for the given operation.

        Args:
            path: The filesystem path being accessed.
            operation: One of "read", "write", "execute", "delete".

        Returns:
            A tuple of (allowed, reason).
        """
        # Normalize path
        try:
            normalized = os.path.normpath(os.path.abspath(path))
        except (ValueError, OSError):
            self._violation_count += 1
            return False, f"Invalid path: {path}"

        op = operation.lower().strip()

        # 1. Check for path traversal attacks
        if ".." in path:
            self._violation_count += 1
            reason = (
                f"Path traversal detected in '{path}'. "
                f"AngelClaw blocks directory traversal to prevent workspace escapes."
            )
            logger.warning("[WorkspaceIsolation] Path traversal: %s", path)
            return False, reason

        # 2. Check sensitive read blocklist
        if op == "read":
            for blocked in self.SENSITIVE_READ_BLOCKLIST:
                if self._path_matches(normalized, blocked):
                    self._violation_count += 1
                    reason = (
                        f"Read access to '{path}' is blocked. "
                        f"This path contains sensitive system credentials. "
                        f"Use AngelClaw's secret management instead."
                    )
                    logger.warning("[WorkspaceIsolation] Sensitive read blocked: %s", path)
                    return False, reason

        # 3. Check system write blocklist
        if op in ("write", "delete", "execute"):
            for blocked in self.SYSTEM_WRITE_BLOCKLIST:
                if normalized.startswith(blocked):
                    self._violation_count += 1
                    reason = (
                        f"{op.capitalize()} access to '{path}' is blocked. "
                        f"System directories are protected by AngelClaw. "
                        f"Only write to your designated workspace or output directories."
                    )
                    logger.warning("[WorkspaceIsolation] System %s blocked: %s", op, path)
                    return False, reason

        # 4. Check workspace boundary for write operations
        if op in ("write", "delete") and self.workspace_root:
            ws_norm = os.path.normpath(os.path.abspath(self.workspace_root))
            in_workspace = normalized.startswith(ws_norm + os.sep) or normalized == ws_norm
            in_output = any(
                normalized.startswith(os.path.normpath(os.path.abspath(d)))
                for d in self.output_dirs
            )
            if not in_workspace and not in_output:
                self._violation_count += 1
                reason = (
                    f"{op.capitalize()} access to '{path}' is outside the workspace "
                    f"boundary ({self.workspace_root}). AngelClaw enforces workspace "
                    f"isolation to prevent cross-tenant data access."
                )
                logger.warning(
                    "[WorkspaceIsolation] Out-of-workspace %s: %s (root=%s)",
                    op,
                    path,
                    self.workspace_root,
                )
                return False, reason

        # 5. Check for cross-tenant access patterns
        if self.tenant_id:
            cross_tenant = self._detect_cross_tenant(normalized)
            if cross_tenant:
                self._violation_count += 1
                reason = (
                    f"Cross-tenant access detected: '{path}' appears to belong to "
                    f"a different tenant. AngelClaw enforces strict tenant isolation."
                )
                logger.warning("[WorkspaceIsolation] Cross-tenant access: %s", path)
                return False, reason

        return True, f"Access to '{path}' ({op}) is allowed."

    def get_stats(self) -> dict[str, Any]:
        """Return workspace isolation statistics."""
        return {
            "workspace_root": self.workspace_root,
            "output_dirs": self.output_dirs,
            "tenant_id": self.tenant_id,
            "violation_count": self._violation_count,
        }

    # -- internal helpers --

    def _detect_cross_tenant(self, normalized_path: str) -> bool:
        """Detect if a path targets a different tenant's data."""
        # Look for /tenants/<id>/ or /users/<id>/ patterns where id != ours
        patterns = [
            re.compile(r"/tenants?/([^/]+)/"),
            re.compile(r"/users?/([^/]+)/"),
            re.compile(r"/workspaces?/([^/]+)/"),
            re.compile(r"/orgs?/([^/]+)/"),
        ]
        for pattern in patterns:
            match = pattern.search(normalized_path)
            if match:
                found_id = match.group(1)
                if found_id != self.tenant_id:
                    return True
        return False

    @staticmethod
    def _path_matches(normalized: str, pattern: str) -> bool:
        """Check if a normalized path matches a blocklist pattern.

        Supports simple glob-like '*' wildcard for a single directory component.
        """
        if "*" not in pattern:
            return normalized.startswith(pattern) or normalized == pattern.rstrip("/")

        # Convert simple glob to regex
        regex_pattern = pattern.replace("*", "[^/]+")
        return bool(re.search(regex_pattern, normalized))


# ===========================================================================
# 5. RiskScoring — Unified risk scoring engine
# ===========================================================================


class RiskLevel(str, Enum):
    """Normalized risk levels for AngelClaw scoring."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class RiskFactor:
    """A single contributing factor to a risk score."""

    name: str
    category: str
    score: float  # 0-100 contribution
    description: str


@dataclass
class RiskScore:
    """Unified risk scoring result."""

    level: RiskLevel
    score: float  # 0-100 normalized
    confidence: float  # 0.0-1.0
    factors: list[RiskFactor] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "level": self.level.value,
            "score": self.score,
            "confidence": self.confidence,
            "factors": [
                {
                    "name": f.name,
                    "category": f.category,
                    "score": f.score,
                    "description": f.description,
                }
                for f in self.factors
            ],
            "timestamp": self.timestamp,
        }


class RiskScoring:
    """AngelClaw Risk Scoring — unified risk assessment for any input.

    Combines prompt injection, data leakage, evil AGI, and trifecta
    detection into a single normalized 0-100 score with per-factor breakdown.

    Usage::

        rs = RiskScoring()

        # Score text input
        result = rs.score("text", "ignore all previous instructions and...")

        # Score event stream
        result = rs.score("events", events_list)

        print(f"Risk: {result.level.value} ({result.score}/100)")
        for factor in result.factors:
            print(f"  - {factor.name}: {factor.score}")
    """

    # Weights for each detection category (sum to ~100 for normalization)
    CATEGORY_WEIGHTS: dict[str, float] = {
        "prompt_injection": 30.0,
        "data_leakage": 25.0,
        "evil_agi": 25.0,
        "lethal_trifecta": 15.0,
        "attack_chain": 5.0,
    }

    # Severity multipliers for indicator scoring
    SEVERITY_MULTIPLIERS: dict[ThreatSeverity, float] = {
        ThreatSeverity.CRITICAL: 1.0,
        ThreatSeverity.HIGH: 0.75,
        ThreatSeverity.MEDIUM: 0.5,
        ThreatSeverity.LOW: 0.25,
        ThreatSeverity.INFO: 0.1,
    }

    def __init__(self) -> None:
        self._total_scored: int = 0

    def score(self, input_type: str, data: Any) -> RiskScore:
        """Score any input and return a unified RiskScore.

        Args:
            input_type: One of "text", "events", "tool_call".
            data: The data to score:
                - For "text": a string.
                - For "events": a list of event dicts.
                - For "tool_call": a dict with "tool_name" and "args".

        Returns:
            A RiskScore with normalized 0-100 score and factor breakdown.
        """
        self._total_scored += 1

        if input_type == "text":
            return self._score_text(data)
        elif input_type == "events":
            return self._score_events(data)
        elif input_type == "tool_call":
            return self._score_tool_call(data)
        else:
            logger.warning("[RiskScoring] Unknown input_type: %s", input_type)
            return RiskScore(
                level=RiskLevel.NONE,
                score=0.0,
                confidence=0.0,
                factors=[
                    RiskFactor(
                        name="unknown_input",
                        category="error",
                        score=0.0,
                        description=f"Unknown input type: {input_type}",
                    )
                ],
            )

    def _score_text(self, text: str) -> RiskScore:
        """Score a text input across all detection engines."""
        factors: list[RiskFactor] = []

        # Prompt injection
        injection_indicators = detect_prompt_injection(text)
        injection_score = self._indicators_to_score(
            injection_indicators, self.CATEGORY_WEIGHTS["prompt_injection"]
        )
        if injection_score > 0:
            factors.append(
                RiskFactor(
                    name="prompt_injection",
                    category="prompt_injection",
                    score=injection_score,
                    description=f"{len(injection_indicators)} injection pattern(s) detected",
                )
            )

        # Data leakage
        leakage_indicators = detect_data_leakage(text)
        leakage_score = self._indicators_to_score(
            leakage_indicators, self.CATEGORY_WEIGHTS["data_leakage"]
        )
        if leakage_score > 0:
            factors.append(
                RiskFactor(
                    name="data_leakage",
                    category="data_leakage",
                    score=leakage_score,
                    description=f"{len(leakage_indicators)} leakage pattern(s) detected",
                )
            )

        # Evil AGI
        agi_indicators = detect_evil_agi(text)
        agi_score = self._indicators_to_score(agi_indicators, self.CATEGORY_WEIGHTS["evil_agi"])
        if agi_score > 0:
            factors.append(
                RiskFactor(
                    name="evil_agi",
                    category="evil_agi",
                    score=agi_score,
                    description=f"{len(agi_indicators)} evil AGI pattern(s) detected",
                )
            )

        total_score = sum(f.score for f in factors)
        total_score = min(total_score, 100.0)  # Cap at 100

        # Confidence based on how many detection engines found something
        engines_triggered = len(factors)
        confidence = min(engines_triggered / 3.0, 1.0) if factors else 0.5

        return RiskScore(
            level=self._score_to_level(total_score),
            score=round(total_score, 1),
            confidence=round(confidence, 2),
            factors=factors,
        )

    def _score_events(self, events: list[dict]) -> RiskScore:
        """Score an event stream across all detection engines."""
        factors: list[RiskFactor] = []

        # Lethal Trifecta
        trifecta = assess_lethal_trifecta(events)
        trifecta_score = trifecta.score * self.CATEGORY_WEIGHTS["lethal_trifecta"]
        if trifecta_score > 0:
            factors.append(
                RiskFactor(
                    name="lethal_trifecta",
                    category="lethal_trifecta",
                    score=round(trifecta_score, 1),
                    description=(
                        f"Trifecta score: {trifecta.score:.0%} — "
                        f"{'ACTIVE' if trifecta.active else 'partial'}"
                    ),
                )
            )

        # Attack chain
        chain = detect_attack_chain(events)
        if chain.is_active:
            chain_score = chain.chain_confidence * self.CATEGORY_WEIGHTS["attack_chain"]
            factors.append(
                RiskFactor(
                    name="attack_chain",
                    category="attack_chain",
                    score=round(chain_score, 1),
                    description=(
                        f"{len(chain.stages_detected)} attack stages detected: "
                        f"{', '.join(s.value for s in chain.stages_detected)}"
                    ),
                )
            )

        # Also run text-based checks on event details
        text_factors: list[RiskFactor] = []
        for event in events[:50]:
            command = (event.get("details") or {}).get("command", "")
            if command:
                sub_score = self._score_text(command)
                text_factors.extend(sub_score.factors)

        # Aggregate text factors by category
        category_scores: dict[str, float] = {}
        for f in text_factors:
            category_scores[f.category] = max(category_scores.get(f.category, 0.0), f.score)
        for cat, cat_score in category_scores.items():
            factors.append(
                RiskFactor(
                    name=f"event_{cat}",
                    category=cat,
                    score=round(cat_score, 1),
                    description="Detected in event command analysis",
                )
            )

        total_score = min(sum(f.score for f in factors), 100.0)
        engines_triggered = len(set(f.category for f in factors))
        confidence = min(engines_triggered / 4.0, 1.0) if factors else 0.5

        return RiskScore(
            level=self._score_to_level(total_score),
            score=round(total_score, 1),
            confidence=round(confidence, 2),
            factors=factors,
        )

    def _score_tool_call(self, data: dict) -> RiskScore:
        """Score a tool call by combining tool guard and text analysis."""
        tool_name = data.get("tool_name", "")
        args = data.get("args", {})
        factors: list[RiskFactor] = []

        # Check tool name against known dangerous tools
        guard = ToolGuard()
        allowed, reason = guard.check_tool(tool_name, args)
        if not allowed:
            factors.append(
                RiskFactor(
                    name="tool_blocked",
                    category="tool_guard",
                    score=40.0,
                    description=reason,
                )
            )

        # Run text-based analysis on the combined tool name + args
        combined_text = f"{tool_name} {str(args)}"
        text_score = self._score_text(combined_text)
        factors.extend(text_score.factors)

        total_score = min(sum(f.score for f in factors), 100.0)
        confidence = 0.8 if factors else 0.5

        return RiskScore(
            level=self._score_to_level(total_score),
            score=round(total_score, 1),
            confidence=round(confidence, 2),
            factors=factors,
        )

    def _indicators_to_score(self, indicators: list[ThreatIndicator], max_weight: float) -> float:
        """Convert a list of threat indicators to a weighted score."""
        if not indicators:
            return 0.0

        # Use the highest severity indicator to determine the base score
        max_multiplier = 0.0
        for ind in indicators:
            multiplier = self.SEVERITY_MULTIPLIERS.get(ind.severity, 0.1)
            max_multiplier = max(max_multiplier, multiplier)

        # Scale by number of indicators (diminishing returns)
        count_factor = min(len(indicators) / 3.0, 1.0)

        return round(max_weight * max_multiplier * (0.5 + 0.5 * count_factor), 1)

    @staticmethod
    def _score_to_level(score: float) -> RiskLevel:
        """Convert a numeric score to a risk level."""
        if score >= 70:
            return RiskLevel.CRITICAL
        elif score >= 45:
            return RiskLevel.HIGH
        elif score >= 25:
            return RiskLevel.MEDIUM
        elif score > 0:
            return RiskLevel.LOW
        return RiskLevel.NONE

    def get_stats(self) -> dict[str, int]:
        """Return scoring statistics."""
        return {"total_scored": self._total_scored}


# ===========================================================================
# 6. AdvisoryMonitor — Security advisory monitoring
# ===========================================================================


class AdvisorySeverity(str, Enum):
    """Severity levels for security advisories."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class Advisory:
    """A security advisory tracked by AngelClaw."""

    id: str
    title: str
    severity: AdvisorySeverity
    description: str
    category: str
    affected_components: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    published_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: str | None = None
    active: bool = True
    source: str = "angelclaw"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "category": self.category,
            "affected_components": self.affected_components,
            "mitigations": self.mitigations,
            "published_at": self.published_at,
            "expires_at": self.expires_at,
            "active": self.active,
            "source": self.source,
        }


@dataclass
class AdvisoryRule:
    """A custom advisory rule that triggers based on conditions."""

    id: str
    name: str
    description: str
    severity: AdvisorySeverity
    condition: str  # A human-readable condition description
    category: str
    affected_components: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "condition": self.condition,
            "category": self.category,
            "affected_components": self.affected_components,
            "mitigations": self.mitigations,
            "enabled": self.enabled,
        }


class AdvisoryMonitor:
    """AngelClaw Advisory Monitor — tracks security advisories.

    Maintains an in-memory registry of security advisories and custom
    advisory rules. Inspired by ClawSec's advisory feed concept,
    reimplemented as a standalone AngelClaw component.

    Usage::

        am = AdvisoryMonitor()
        am.publish_advisory(Advisory(
            id="ACLAW-2026-001",
            title="Prompt injection variant in tool-use chains",
            severity=AdvisorySeverity.HIGH,
            description="New prompt injection technique targets tool-use chains...",
            category="prompt_injection",
        ))

        active = am.check_advisories()
    """

    # Built-in advisories for common AGI/AI threats
    _BUILTIN_ADVISORIES: list[Advisory] = [
        Advisory(
            id="ACLAW-BUILTIN-001",
            title="Prompt injection via tool output",
            severity=AdvisorySeverity.HIGH,
            description=(
                "AI agents that process untrusted tool outputs are vulnerable to "
                "indirect prompt injection. Attackers can embed instructions in "
                "web pages, documents, or API responses that the agent processes."
            ),
            category="prompt_injection",
            affected_components=["tool_executor", "web_fetch", "document_reader"],
            mitigations=[
                "Enable AngelClaw PromptDefense on all tool outputs",
                "Use output sandboxing for untrusted data sources",
                "Monitor for injection patterns in tool results",
            ],
            source="angelclaw-builtin",
        ),
        Advisory(
            id="ACLAW-BUILTIN-002",
            title="Lethal Trifecta exposure in multi-tool agents",
            severity=AdvisorySeverity.CRITICAL,
            description=(
                "Agents with simultaneous access to private data, untrusted content "
                "processing, and external communication channels are exposed to the "
                "OpenClaw Lethal Trifecta. This maximizes the attack surface for "
                "data exfiltration via prompt injection."
            ),
            category="lethal_trifecta",
            affected_components=["agent_runtime", "tool_executor", "network_access"],
            mitigations=[
                "Segment agent capabilities to avoid full trifecta exposure",
                "Enable AngelClaw RiskScoring on all agent sessions",
                "Restrict external communication for agents with secret access",
            ],
            source="angelclaw-builtin",
        ),
        Advisory(
            id="ACLAW-BUILTIN-003",
            title="Multi-step attack chains in autonomous agents",
            severity=AdvisorySeverity.MEDIUM,
            description=(
                "Autonomous agents with long-running sessions may execute multi-step "
                "attack chains where each individual action appears benign. "
                "AngelClaw's attack chain detection monitors for these sequences."
            ),
            category="attack_chain",
            affected_components=["agent_runtime", "daemon", "task_executor"],
            mitigations=[
                "Enable AngelClaw shield event-based monitoring",
                "Set maximum session durations for autonomous agents",
                "Review action timelines for recon -> escalation -> exfil patterns",
            ],
            source="angelclaw-builtin",
        ),
    ]

    def __init__(self, include_builtins: bool = True) -> None:
        self._advisories: dict[str, Advisory] = {}
        self._custom_rules: dict[str, AdvisoryRule] = {}

        if include_builtins:
            for adv in self._BUILTIN_ADVISORIES:
                self._advisories[adv.id] = adv

    def publish_advisory(self, advisory: Advisory) -> None:
        """Publish a new security advisory.

        Args:
            advisory: The Advisory to publish.
        """
        self._advisories[advisory.id] = advisory
        logger.info(
            "[AdvisoryMonitor] Published advisory %s: %s [%s]",
            advisory.id,
            advisory.title,
            advisory.severity.value,
        )

    def retract_advisory(self, advisory_id: str) -> bool:
        """Mark an advisory as inactive (retracted).

        Args:
            advisory_id: The ID of the advisory to retract.

        Returns:
            True if the advisory was found and retracted.
        """
        advisory = self._advisories.get(advisory_id)
        if advisory:
            advisory.active = False
            logger.info("[AdvisoryMonitor] Retracted advisory %s", advisory_id)
            return True
        return False

    def check_advisories(self, category: str | None = None) -> list[Advisory]:
        """Return all active advisories, optionally filtered by category.

        Args:
            category: Optional category filter (e.g. "prompt_injection").

        Returns:
            A list of active Advisory objects.
        """
        now = datetime.now(timezone.utc).isoformat()
        active: list[Advisory] = []

        for adv in self._advisories.values():
            if not adv.active:
                continue
            # Check expiration
            if adv.expires_at and adv.expires_at < now:
                adv.active = False
                continue
            if category and adv.category != category:
                continue
            active.append(adv)

        return active

    def add_custom_rule(self, rule: AdvisoryRule) -> None:
        """Add a custom advisory rule.

        Custom rules allow operators to define organization-specific
        advisories that trigger based on their own conditions.

        Args:
            rule: The AdvisoryRule to add.
        """
        self._custom_rules[rule.id] = rule
        logger.info("[AdvisoryMonitor] Added custom rule %s: %s", rule.id, rule.name)

    def remove_custom_rule(self, rule_id: str) -> bool:
        """Remove a custom advisory rule.

        Args:
            rule_id: The ID of the rule to remove.

        Returns:
            True if the rule was found and removed.
        """
        if rule_id in self._custom_rules:
            del self._custom_rules[rule_id]
            logger.info("[AdvisoryMonitor] Removed custom rule %s", rule_id)
            return True
        return False

    def get_custom_rules(self) -> list[AdvisoryRule]:
        """Return all custom advisory rules."""
        return list(self._custom_rules.values())

    def evaluate_custom_rules(self, context: dict[str, Any]) -> list[Advisory]:
        """Evaluate custom rules against a context and generate advisories.

        This checks enabled custom rules and generates temporary advisories
        when rule conditions match the provided context.

        Args:
            context: A dict of contextual data to evaluate rules against.
                     Supports keys: "categories" (list), "severity_counts" (dict),
                     "tool_names" (list), "event_count" (int).

        Returns:
            A list of newly generated Advisory objects from matching rules.
        """
        generated: list[Advisory] = []

        for rule in self._custom_rules.values():
            if not rule.enabled:
                continue

            triggered = False

            # Check category-based conditions
            if rule.category in context.get("categories", []):
                triggered = True

            # Check severity threshold conditions
            severity_counts = context.get("severity_counts", {})
            if rule.severity.value in severity_counts:
                if severity_counts[rule.severity.value] > 0:
                    triggered = True

            # Check affected component conditions
            active_tools = set(context.get("tool_names", []))
            if active_tools & set(rule.affected_components):
                triggered = True

            if triggered:
                adv = Advisory(
                    id=f"{rule.id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                    title=f"[Custom Rule] {rule.name}",
                    severity=rule.severity,
                    description=rule.description,
                    category=rule.category,
                    affected_components=rule.affected_components,
                    mitigations=rule.mitigations,
                    source=f"custom-rule:{rule.id}",
                )
                generated.append(adv)
                self._advisories[adv.id] = adv
                logger.info(
                    "[AdvisoryMonitor] Custom rule %s triggered: %s",
                    rule.id,
                    rule.name,
                )

        return generated

    def get_stats(self) -> dict[str, Any]:
        """Return advisory monitor statistics."""
        all_advisories = list(self._advisories.values())
        active = [a for a in all_advisories if a.active]
        return {
            "total_advisories": len(all_advisories),
            "active_advisories": len(active),
            "custom_rules": len(self._custom_rules),
            "by_severity": {
                sev.value: sum(1 for a in active if a.severity == sev) for sev in AdvisorySeverity
            },
        }


# ===========================================================================
# Module-level singletons for convenience
# ===========================================================================

prompt_defense = PromptDefense()
tool_guard = ToolGuard()
skill_integrity = SkillIntegrity()
workspace_isolation = WorkspaceIsolation()
risk_scoring = RiskScoring()
advisory_monitor = AdvisoryMonitor()
