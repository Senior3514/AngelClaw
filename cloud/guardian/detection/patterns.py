"""AngelClaw – Pattern-based threat detection.

Matches incoming events against a library of known-dangerous patterns.
Each pattern returns a ThreatIndicator when triggered.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict

from cloud.db.models import EventRow
from cloud.guardian.models import MitreTactic, ThreatIndicator

logger = logging.getLogger("angelgrid.cloud.guardian.detection.patterns")


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------


class PatternDetector:
    """Stateless pattern matcher run against event batches or windows."""

    def detect(
        self,
        events: list[EventRow],
        window_seconds: int = 300,
    ) -> list[ThreatIndicator]:
        """Run all pattern checks and return indicators found."""
        indicators: list[ThreatIndicator] = []
        if not events:
            return indicators

        indicators.extend(self._check_repeated_secret_exfil(events))
        indicators.extend(self._check_high_severity_burst(events))
        indicators.extend(self._check_credential_stuffing(events, window_seconds))
        indicators.extend(self._check_data_staging(events, window_seconds))
        indicators.extend(self._check_privilege_chain(events, window_seconds))
        indicators.extend(self._check_lateral_movement(events, window_seconds))
        indicators.extend(self._check_policy_tampering(events))
        # V2.1 — expanded pattern detections
        indicators.extend(self._check_recon_chain(events, window_seconds))
        indicators.extend(self._check_encoding_exfil(events))
        indicators.extend(self._check_tool_abuse(events, window_seconds))
        indicators.extend(self._check_resource_exhaustion(events))
        indicators.extend(self._check_persistence_install(events))
        # V2.2 — advanced pattern detections
        indicators.extend(self._check_dns_tunneling(events))
        indicators.extend(self._check_lolbin_abuse(events))
        indicators.extend(self._check_fileless_malware(events))
        indicators.extend(self._check_token_replay(events, window_seconds))
        indicators.extend(self._check_cloud_api_abuse(events, window_seconds))
        indicators.extend(self._check_reverse_proxy_abuse(events))
        indicators.extend(self._check_defense_evasion(events))
        indicators.extend(self._check_multi_agent_coordination(events, window_seconds))

        for ind in indicators:
            logger.info(
                "[PATTERN] %s | severity=%s confidence=%.2f | %s",
                ind.pattern_name,
                ind.severity,
                ind.confidence,
                ind.description,
            )
        return indicators

    # ---------------------------------------------------------------
    # Individual patterns
    # ---------------------------------------------------------------

    def _check_repeated_secret_exfil(
        self,
        events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """>=2 secret-access events in a batch → critical."""
        secret_events = [e for e in events if (e.details or {}).get("accesses_secrets") is True]
        if len(secret_events) < 2:
            return []
        agents = list({e.agent_id for e in secret_events})
        return [
            ThreatIndicator(
                indicator_type="pattern_match",
                pattern_name="repeated_secret_exfil",
                severity="critical",
                confidence=0.95,
                description=(
                    f"Repeated secret access: {len(secret_events)} events "
                    f"from {len(agents)} agent(s)"
                ),
                related_event_ids=[e.id for e in secret_events],
                related_agent_ids=agents,
                suggested_playbook="quarantine_agent",
                mitre_tactic=MitreTactic.CREDENTIAL_ACCESS.value,
            )
        ]

    def _check_high_severity_burst(
        self,
        events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """>=5 high/critical events from one agent → high."""
        agent_counts: Counter[str] = Counter()
        agent_events: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            if e.severity in ("high", "critical"):
                agent_counts[e.agent_id] += 1
                agent_events[e.agent_id].append(e)

        indicators = []
        for agent_id, count in agent_counts.items():
            if count >= 5:
                evts = agent_events[agent_id]
                indicators.append(
                    ThreatIndicator(
                        indicator_type="pattern_match",
                        pattern_name="high_severity_burst",
                        severity="high",
                        confidence=0.85,
                        description=(
                            f"Severity burst: {count} high/critical events "
                            f"from agent {agent_id[:8]}"
                        ),
                        related_event_ids=[e.id for e in evts],
                        related_agent_ids=[agent_id],
                        suggested_playbook="throttle_agent",
                        mitre_tactic=MitreTactic.IMPACT.value,
                    )
                )
        return indicators

    def _check_credential_stuffing(
        self,
        events: list[EventRow],
        window_seconds: int,
    ) -> list[ThreatIndicator]:
        """>5 failed auth attempts from same source in window → high."""
        auth_failures: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            if e.type and "auth" in e.type.lower() and e.severity in ("high", "critical"):
                source = (e.details or {}).get("source", e.agent_id)
                auth_failures[source].append(e)

        indicators = []
        for source, evts in auth_failures.items():
            if len(evts) >= 5:
                indicators.append(
                    ThreatIndicator(
                        indicator_type="pattern_match",
                        pattern_name="credential_stuffing",
                        severity="high",
                        confidence=0.80,
                        description=(
                            f"Credential stuffing: {len(evts)} auth failures "
                            f"from source {source[:16]}"
                        ),
                        related_event_ids=[e.id for e in evts],
                        related_agent_ids=list({e.agent_id for e in evts}),
                        suggested_playbook="block_source",
                        mitre_tactic=MitreTactic.CREDENTIAL_ACCESS.value,
                    )
                )
        return indicators

    def _check_data_staging(
        self,
        events: list[EventRow],
        window_seconds: int,
    ) -> list[ThreatIndicator]:
        """Large file write followed by network upload within window → critical."""
        per_agent: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            per_agent[e.agent_id].append(e)

        indicators = []
        for agent_id, agent_events in per_agent.items():
            sorted_events = sorted(agent_events, key=lambda e: e.timestamp)
            file_writes = [
                e
                for e in sorted_events
                if e.type and "file" in e.type.lower() and e.severity in ("high", "critical")
            ]
            net_uploads = [
                e
                for e in sorted_events
                if e.type
                and "network" in e.type.lower()
                and (e.details or {}).get("payload_size_bytes", 0) > 500_000
            ]
            for fw in file_writes:
                for nu in net_uploads:
                    delta = (nu.timestamp - fw.timestamp).total_seconds()
                    if 0 < delta <= window_seconds:
                        indicators.append(
                            ThreatIndicator(
                                indicator_type="pattern_match",
                                pattern_name="data_staging",
                                severity="critical",
                                confidence=0.75,
                                description=(
                                    f"Data staging: file write then network upload "
                                    f"within {int(delta)}s from agent {agent_id[:8]}"
                                ),
                                related_event_ids=[fw.id, nu.id],
                                related_agent_ids=[agent_id],
                                suggested_playbook="quarantine_agent",
                                mitre_tactic=MitreTactic.EXFILTRATION.value,
                            )
                        )
                        break  # one indicator per agent
                else:
                    continue
                break
        return indicators

    def _check_privilege_chain(
        self,
        events: list[EventRow],
        window_seconds: int,
    ) -> list[ThreatIndicator]:
        """auth → file → shell from same agent in sequence → high."""
        per_agent: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            if e.type and any(k in (e.type or "").lower() for k in ("auth", "file", "shell")):
                per_agent[e.agent_id].append(e)

        indicators = []
        for agent_id, agent_events in per_agent.items():
            sorted_events = sorted(agent_events, key=lambda e: e.timestamp)
            categories_seen: list[str] = []
            for e in sorted_events:
                cat = (
                    "auth"
                    if "auth" in (e.type or "").lower()
                    else "file"
                    if "file" in (e.type or "").lower()
                    else "shell"
                )
                if not categories_seen or categories_seen[-1] != cat:
                    categories_seen.append(cat)

            if len(categories_seen) >= 3:
                chain_str = " → ".join(categories_seen[:5])
                indicators.append(
                    ThreatIndicator(
                        indicator_type="pattern_match",
                        pattern_name="privilege_chain",
                        severity="high",
                        confidence=0.70,
                        description=(f"Privilege chain: {chain_str} from agent {agent_id[:8]}"),
                        related_event_ids=[e.id for e in sorted_events[:10]],
                        related_agent_ids=[agent_id],
                        suggested_playbook="escalate_to_human",
                        mitre_tactic=MitreTactic.PRIVILEGE_ESCALATION.value,
                    )
                )
        return indicators

    def _check_lateral_movement(
        self,
        events: list[EventRow],
        window_seconds: int,
    ) -> list[ThreatIndicator]:
        """AI tool calls targeting multiple agents rapidly → high."""
        ai_events = [e for e in events if e.type and "ai" in (e.type or "").lower()]
        if len(ai_events) < 3:
            return []

        # Group by source agent, check targets
        source_targets: dict[str, set[str]] = defaultdict(set)
        source_events: dict[str, list[str]] = defaultdict(list)
        for e in ai_events:
            source = (e.details or {}).get("source_agent", e.agent_id)
            target = (e.details or {}).get("target_agent", "")
            if target and target != source:
                source_targets[source].add(target)
                source_events[source].append(e.id)

        indicators = []
        for source, targets in source_targets.items():
            if len(targets) >= 3:
                indicators.append(
                    ThreatIndicator(
                        indicator_type="pattern_match",
                        pattern_name="lateral_movement",
                        severity="high",
                        confidence=0.70,
                        description=(
                            f"Lateral movement: agent {source[:8]} targeted "
                            f"{len(targets)} other agents via AI tool calls"
                        ),
                        related_event_ids=source_events[source][:10],
                        related_agent_ids=[source] + list(targets)[:5],
                        suggested_playbook="quarantine_agent",
                        mitre_tactic=MitreTactic.LATERAL_MOVEMENT.value,
                    )
                )
        return indicators

    def _check_policy_tampering(
        self,
        events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """Attempts to modify policy files or disable rules → critical."""
        tampering = [
            e
            for e in events
            if e.type
            and any(k in (e.type or "").lower() for k in ("policy", "config"))
            and e.severity in ("high", "critical")
        ]
        if not tampering:
            return []

        return [
            ThreatIndicator(
                indicator_type="pattern_match",
                pattern_name="policy_tampering",
                severity="critical",
                confidence=0.90,
                description=(
                    f"Policy tampering: {len(tampering)} suspicious policy/config "
                    f"modification attempt(s)"
                ),
                related_event_ids=[e.id for e in tampering],
                related_agent_ids=list({e.agent_id for e in tampering}),
                suggested_playbook="escalate_to_human",
                mitre_tactic=MitreTactic.PERSISTENCE.value,
            )
        ]


    # ---------------------------------------------------------------
    # V2.1 — New pattern detections
    # ---------------------------------------------------------------

    def _check_recon_chain(
        self,
        events: list[EventRow],
        window_seconds: int,
    ) -> list[ThreatIndicator]:
        """Reconnaissance chain: system info gathering from same agent → high."""
        recon_keywords = {"whoami", "id", "uname", "hostname", "ifconfig", "ip addr",
                          "systeminfo", "ipconfig", "net user", "cat /etc/passwd",
                          "nmap", "nslookup", "dig", "ls /", "find /"}
        per_agent: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            cmd = ((e.details or {}).get("command", "") or "").lower()
            if any(k in cmd for k in recon_keywords):
                per_agent[e.agent_id].append(e)

        indicators = []
        for agent_id, evts in per_agent.items():
            if len(evts) >= 3:
                indicators.append(
                    ThreatIndicator(
                        indicator_type="pattern_match",
                        pattern_name="recon_chain",
                        severity="high",
                        confidence=0.75,
                        description=(
                            f"Reconnaissance chain: {len(evts)} system info gathering "
                            f"commands from agent {agent_id[:8]}"
                        ),
                        related_event_ids=[e.id for e in evts[:10]],
                        related_agent_ids=[agent_id],
                        suggested_playbook="throttle_agent",
                        mitre_tactic=MitreTactic.RECONNAISSANCE.value,
                    )
                )
        return indicators

    def _check_encoding_exfil(
        self,
        events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """Encoding before upload: base64/gzip + network event → critical."""
        per_agent: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            per_agent[e.agent_id].append(e)

        indicators = []
        encoding_keywords = {"base64", "gzip", "tar ", "zip ", "compress", "encode"}
        for agent_id, evts in per_agent.items():
            sorted_evts = sorted(evts, key=lambda e: e.timestamp)
            has_encoding = False
            has_upload = False
            encoding_evts = []
            upload_evts = []
            for e in sorted_evts:
                cmd = ((e.details or {}).get("command", "") or "").lower()
                if any(k in cmd for k in encoding_keywords):
                    has_encoding = True
                    encoding_evts.append(e)
                if e.type and "network" in (e.type or "").lower():
                    has_upload = True
                    upload_evts.append(e)
            if has_encoding and has_upload:
                all_evts = encoding_evts + upload_evts
                indicators.append(
                    ThreatIndicator(
                        indicator_type="pattern_match",
                        pattern_name="encoding_exfil",
                        severity="critical",
                        confidence=0.80,
                        description=(
                            f"Encoding exfiltration: data encoding followed by "
                            f"network upload from agent {agent_id[:8]}"
                        ),
                        related_event_ids=[e.id for e in all_evts[:10]],
                        related_agent_ids=[agent_id],
                        suggested_playbook="quarantine_agent",
                        mitre_tactic=MitreTactic.EXFILTRATION.value,
                    )
                )
        return indicators

    def _check_tool_abuse(
        self,
        events: list[EventRow],
        window_seconds: int,
    ) -> list[ThreatIndicator]:
        """Legitimate tool misuse: rapid diverse tool calls from one agent → high."""
        per_agent: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            if e.type and "ai" in (e.type or "").lower():
                per_agent[e.agent_id].append(e)

        indicators = []
        for agent_id, evts in per_agent.items():
            tool_names = set()
            for e in evts:
                tool = (e.details or {}).get("tool_name", "")
                if tool:
                    tool_names.add(tool)
            if len(tool_names) >= 8 and len(evts) >= 15:
                indicators.append(
                    ThreatIndicator(
                        indicator_type="pattern_match",
                        pattern_name="tool_abuse",
                        severity="high",
                        confidence=0.70,
                        description=(
                            f"Tool abuse: agent {agent_id[:8]} used {len(tool_names)} "
                            f"distinct tools in {len(evts)} calls"
                        ),
                        related_event_ids=[e.id for e in evts[:10]],
                        related_agent_ids=[agent_id],
                        suggested_playbook="throttle_agent",
                        mitre_tactic=MitreTactic.EXECUTION.value,
                    )
                )
        return indicators

    def _check_resource_exhaustion(
        self,
        events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """Resource exhaustion: fork bomb, infinite loop, or stress commands → critical."""
        resource_keywords = {"fork", "while true", ":()", "stress", "stress-ng",
                             "dd if=/dev/zero", "dd if=/dev/urandom", "/dev/null"}
        flagged = []
        for e in events:
            cmd = ((e.details or {}).get("command", "") or "").lower()
            if any(k in cmd for k in resource_keywords):
                flagged.append(e)

        if not flagged:
            return []
        return [
            ThreatIndicator(
                indicator_type="pattern_match",
                pattern_name="resource_exhaustion",
                severity="critical",
                confidence=0.90,
                description=(
                    f"Resource exhaustion: {len(flagged)} commands matching "
                    f"DoS/resource abuse patterns"
                ),
                related_event_ids=[e.id for e in flagged[:10]],
                related_agent_ids=list({e.agent_id for e in flagged}),
                suggested_playbook="quarantine_agent",
                mitre_tactic=MitreTactic.IMPACT.value,
            )
        ]

    def _check_persistence_install(
        self,
        events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """Persistence installation: crontab, systemd, registry modifications → high."""
        persist_keywords = {"crontab", "systemctl enable", "/etc/init.d",
                            "@reboot", "schtasks /create", "reg add",
                            "launchctl load", "startup script"}
        flagged = []
        for e in events:
            cmd = ((e.details or {}).get("command", "") or "").lower()
            if any(k in cmd for k in persist_keywords):
                flagged.append(e)

        if not flagged:
            return []
        return [
            ThreatIndicator(
                indicator_type="pattern_match",
                pattern_name="persistence_install",
                severity="high",
                confidence=0.80,
                description=(
                    f"Persistence installation: {len(flagged)} commands installing "
                    f"persistence mechanisms"
                ),
                related_event_ids=[e.id for e in flagged[:10]],
                related_agent_ids=list({e.agent_id for e in flagged}),
                suggested_playbook="escalate_to_human",
                mitre_tactic=MitreTactic.PERSISTENCE.value,
            )
        ]


    # ---------------------------------------------------------------
    # V2.2 — Advanced pattern detections
    # ---------------------------------------------------------------

    def _check_dns_tunneling(
        self,
        events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """DNS tunneling: long subdomain queries or high-frequency DNS from one agent → critical."""
        dns_keywords = {"nslookup", "dig ", "host ", "dns", "resolve"}
        per_agent: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            cmd = ((e.details or {}).get("command", "") or "").lower()
            etype = (e.type or "").lower()
            if any(k in cmd or k in etype for k in dns_keywords):
                per_agent[e.agent_id].append(e)

        indicators = []
        for agent_id, evts in per_agent.items():
            if len(evts) >= 10:
                indicators.append(
                    ThreatIndicator(
                        indicator_type="pattern_match",
                        pattern_name="dns_tunneling",
                        severity="critical",
                        confidence=0.80,
                        description=(
                            f"DNS tunneling suspected: {len(evts)} DNS-related "
                            f"events from agent {agent_id[:8]}"
                        ),
                        related_event_ids=[e.id for e in evts[:15]],
                        related_agent_ids=[agent_id],
                        suggested_playbook="quarantine_agent",
                        mitre_tactic=MitreTactic.EXFILTRATION.value,
                    )
                )
        return indicators

    def _check_lolbin_abuse(
        self,
        events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """Living-off-the-land binary abuse: legitimate tools used maliciously → high."""
        lolbin_keywords = {
            "certutil", "mshta", "regsvr32", "rundll32", "wscript", "cscript",
            "msiexec", "bitsadmin", "xdg-open", "python -c", "perl -e",
            "ruby -e", "awk '{system", "curl.*|.*sh", "wget.*|.*bash",
        }
        flagged = []
        for e in events:
            cmd = ((e.details or {}).get("command", "") or "").lower()
            if any(k in cmd for k in lolbin_keywords):
                flagged.append(e)

        if len(flagged) < 2:
            return []
        return [
            ThreatIndicator(
                indicator_type="pattern_match",
                pattern_name="lolbin_abuse",
                severity="high",
                confidence=0.75,
                description=(
                    f"LOLBin abuse: {len(flagged)} commands using legitimate binaries "
                    f"in suspicious contexts"
                ),
                related_event_ids=[e.id for e in flagged[:10]],
                related_agent_ids=list({e.agent_id for e in flagged}),
                suggested_playbook="escalate_to_human",
                mitre_tactic=MitreTactic.DEFENSE_EVASION.value,
            )
        ]

    def _check_fileless_malware(
        self,
        events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """Fileless malware indicators: in-memory execution, reflective loading → critical."""
        fileless_keywords = {
            "memfd_create", "/dev/shm/", "process_hollowing", "reflective",
            "powershell -enc", "powershell.exe -enc", "-encodedcommand",
            "iex(", "invoke-expression", "[system.convert]",
            "frombase64string", "/proc/self/mem", "ld_preload",
        }
        flagged = []
        for e in events:
            cmd = ((e.details or {}).get("command", "") or "").lower()
            if any(k in cmd for k in fileless_keywords):
                flagged.append(e)

        if not flagged:
            return []
        return [
            ThreatIndicator(
                indicator_type="pattern_match",
                pattern_name="fileless_malware",
                severity="critical",
                confidence=0.85,
                description=(
                    f"Fileless malware indicators: {len(flagged)} commands matching "
                    f"in-memory execution patterns"
                ),
                related_event_ids=[e.id for e in flagged[:10]],
                related_agent_ids=list({e.agent_id for e in flagged}),
                suggested_playbook="quarantine_agent",
                mitre_tactic=MitreTactic.EXECUTION.value,
            )
        ]

    def _check_token_replay(
        self,
        events: list[EventRow],
        window_seconds: int,
    ) -> list[ThreatIndicator]:
        """Token replay: same auth token used from multiple agents → critical."""
        token_events: dict[str, set[str]] = defaultdict(set)  # token → agents
        token_evts: dict[str, list[str]] = defaultdict(list)
        for e in events:
            details = e.details or {}
            token = details.get("token_hash", "") or details.get("session_id", "")
            if token and len(token) >= 8:
                token_events[token].add(e.agent_id)
                token_evts[token].append(e.id)

        indicators = []
        for token, agents in token_events.items():
            if len(agents) >= 2:
                indicators.append(
                    ThreatIndicator(
                        indicator_type="pattern_match",
                        pattern_name="token_replay",
                        severity="critical",
                        confidence=0.90,
                        description=(
                            f"Token replay attack: same credential used across "
                            f"{len(agents)} agents"
                        ),
                        related_event_ids=token_evts[token][:10],
                        related_agent_ids=list(agents),
                        suggested_playbook="quarantine_agent",
                        mitre_tactic=MitreTactic.CREDENTIAL_ACCESS.value,
                    )
                )
        return indicators

    def _check_cloud_api_abuse(
        self,
        events: list[EventRow],
        window_seconds: int,
    ) -> list[ThreatIndicator]:
        """Cloud API abuse: rapid cloud management API calls → high."""
        cloud_keywords = {
            "aws ", "az ", "gcloud", "kubectl", "terraform", "pulumi",
            "s3api", "ec2", "iam", "cloudformation", "lambda",
        }
        per_agent: dict[str, list[EventRow]] = defaultdict(list)
        for e in events:
            cmd = ((e.details or {}).get("command", "") or "").lower()
            if any(k in cmd for k in cloud_keywords):
                per_agent[e.agent_id].append(e)

        indicators = []
        for agent_id, evts in per_agent.items():
            if len(evts) >= 8:
                indicators.append(
                    ThreatIndicator(
                        indicator_type="pattern_match",
                        pattern_name="cloud_api_abuse",
                        severity="high",
                        confidence=0.75,
                        description=(
                            f"Cloud API abuse: {len(evts)} cloud management commands "
                            f"from agent {agent_id[:8]}"
                        ),
                        related_event_ids=[e.id for e in evts[:10]],
                        related_agent_ids=[agent_id],
                        suggested_playbook="throttle_agent",
                        mitre_tactic=MitreTactic.COLLECTION.value,
                    )
                )
        return indicators

    def _check_reverse_proxy_abuse(
        self,
        events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """Reverse proxy/tunneling abuse: ngrok, bore, cloudflare tunnel → high."""
        proxy_keywords = {
            "ngrok", "bore", "cloudflared tunnel", "localtunnel",
            "serveo", "pagekite", "teleconsole", "sshuttle",
        }
        flagged = []
        for e in events:
            cmd = ((e.details or {}).get("command", "") or "").lower()
            if any(k in cmd for k in proxy_keywords):
                flagged.append(e)

        if not flagged:
            return []
        return [
            ThreatIndicator(
                indicator_type="pattern_match",
                pattern_name="reverse_proxy_abuse",
                severity="high",
                confidence=0.80,
                description=(
                    f"Reverse proxy/tunneling: {len(flagged)} events establishing "
                    f"external tunnels to internal services"
                ),
                related_event_ids=[e.id for e in flagged[:10]],
                related_agent_ids=list({e.agent_id for e in flagged}),
                suggested_playbook="escalate_to_human",
                mitre_tactic=MitreTactic.COMMAND_AND_CONTROL.value,
            )
        ]

    def _check_defense_evasion(
        self,
        events: list[EventRow],
    ) -> list[ThreatIndicator]:
        """Defense evasion: log clearing, history tampering, timestamp modification → critical."""
        evasion_keywords = {
            "history -c", "unset histfile", "shred", "clear_log",
            "wevtutil cl", "rm -f /var/log", "touch -t", "timestomp",
            "auditctl -D", "setenforce 0", "apparmor_parser -R",
        }
        flagged = []
        for e in events:
            cmd = ((e.details or {}).get("command", "") or "").lower()
            if any(k in cmd for k in evasion_keywords):
                flagged.append(e)

        if not flagged:
            return []
        return [
            ThreatIndicator(
                indicator_type="pattern_match",
                pattern_name="defense_evasion",
                severity="critical",
                confidence=0.90,
                description=(
                    f"Defense evasion: {len(flagged)} commands attempting to "
                    f"clear logs, tamper with history, or disable security controls"
                ),
                related_event_ids=[e.id for e in flagged[:10]],
                related_agent_ids=list({e.agent_id for e in flagged}),
                suggested_playbook="quarantine_agent",
                mitre_tactic=MitreTactic.DEFENSE_EVASION.value,
            )
        ]

    def _check_multi_agent_coordination(
        self,
        events: list[EventRow],
        window_seconds: int,
    ) -> list[ThreatIndicator]:
        """Multi-agent coordination: >=3 agents same action type simultaneously."""
        type_agents: dict[str, set[str]] = defaultdict(set)
        type_evts: dict[str, list[str]] = defaultdict(list)
        for e in events:
            if e.type and e.severity in ("high", "critical"):
                type_agents[e.type].add(e.agent_id)
                type_evts[e.type].append(e.id)

        indicators = []
        for etype, agents in type_agents.items():
            if len(agents) >= 3:
                indicators.append(
                    ThreatIndicator(
                        indicator_type="pattern_match",
                        pattern_name="multi_agent_coordination",
                        severity="high",
                        confidence=0.75,
                        description=(
                            f"Coordinated attack: {len(agents)} agents performing "
                            f"'{etype}' actions simultaneously"
                        ),
                        related_event_ids=type_evts[etype][:15],
                        related_agent_ids=list(agents),
                        suggested_playbook="escalate_to_human",
                        mitre_tactic=MitreTactic.LATERAL_MOVEMENT.value,
                    )
                )
        return indicators


# Module-level singleton
pattern_detector = PatternDetector()
