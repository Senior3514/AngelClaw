"""Tests for V5.0 Transcendence: AI Orchestrator, NL Policy, Incident Commander,
Threat Sharing, Deception, Forensics, Compliance-as-Code, Evolving Rules."""

from __future__ import annotations

import hashlib

from cloud.services.ai_orchestrator import AIOrchestorService
from cloud.services.nl_policy import NLPolicyService
from cloud.services.incident_commander import IncidentCommanderService
from cloud.services.threat_sharing import ThreatSharingService
from cloud.services.deception import DeceptionService
from cloud.services.forensics_auto import ForensicsService
from cloud.services.compliance_code import ComplianceCodeService
from cloud.services.evolving_rules import EvolvingRulesService


TENANT = "test-tenant"


# ---------------------------------------------------------------------------
# AIOrchestorService
# ---------------------------------------------------------------------------

class TestAIOrchestorRegistration:
    """Register, list, update, and remove AI models."""

    def test_register_model(self):
        svc = AIOrchestorService()
        model = svc.register_model(
            tenant_id=TENANT,
            name="gpt-4",
            model_type="llm",
            provider="openai",
            capabilities=["text-generation", "summarization"],
            priority=3,
        )
        assert model["name"] == "gpt-4"
        assert model["model_type"] == "llm"
        assert model["provider"] == "openai"
        assert model["enabled"] is True
        assert model["priority"] == 3
        assert "text-generation" in model["capabilities"]

    def test_list_models(self):
        svc = AIOrchestorService()
        svc.register_model(TENANT, "model-a", "llm", "openai", priority=5)
        svc.register_model(TENANT, "model-b", "vision", "anthropic", priority=2)
        models = svc.list_models(TENANT)
        assert len(models) == 2
        # Sorted by priority ascending
        assert models[0]["name"] == "model-b"
        assert models[1]["name"] == "model-a"

    def test_list_models_filter_by_type(self):
        svc = AIOrchestorService()
        svc.register_model(TENANT, "llm-1", "llm", "openai")
        svc.register_model(TENANT, "vis-1", "vision", "google")
        models = svc.list_models(TENANT, model_type="llm")
        assert len(models) == 1
        assert models[0]["name"] == "llm-1"

    def test_list_models_filter_by_capability(self):
        svc = AIOrchestorService()
        svc.register_model(TENANT, "m1", "llm", "openai", capabilities=["code"])
        svc.register_model(TENANT, "m2", "llm", "anthropic", capabilities=["summarization"])
        models = svc.list_models(TENANT, capability="code")
        assert len(models) == 1
        assert models[0]["name"] == "m1"

    def test_get_model(self):
        svc = AIOrchestorService()
        created = svc.register_model(TENANT, "my-model", "llm", "local")
        fetched = svc.get_model(created["id"])
        assert fetched is not None
        assert fetched["name"] == "my-model"

    def test_get_model_not_found(self):
        svc = AIOrchestorService()
        assert svc.get_model("nonexistent") is None

    def test_update_model_priority_and_enabled(self):
        svc = AIOrchestorService()
        model = svc.register_model(TENANT, "updatable", "llm", "azure")
        updated = svc.update_model(model["id"], priority=1, enabled=False)
        assert updated is not None
        assert updated["priority"] == 1
        assert updated["enabled"] is False

    def test_update_model_capabilities(self):
        svc = AIOrchestorService()
        model = svc.register_model(TENANT, "cap-model", "llm", "openai", capabilities=["code"])
        updated = svc.update_model(model["id"], capabilities=["code", "summarization"])
        assert updated is not None
        assert "summarization" in updated["capabilities"]

    def test_update_model_not_found(self):
        svc = AIOrchestorService()
        assert svc.update_model("no-such-id") is None

    def test_remove_model(self):
        svc = AIOrchestorService()
        model = svc.register_model(TENANT, "temp", "llm", "local")
        result = svc.remove_model(model["id"])
        assert result is not None
        assert result["removed"] == model["id"]
        assert svc.list_models(TENANT) == []

    def test_remove_model_not_found(self):
        svc = AIOrchestorService()
        assert svc.remove_model("ghost") is None

    def test_priority_clamped(self):
        svc = AIOrchestorService()
        model = svc.register_model(TENANT, "clamped", "llm", "local", priority=99)
        assert model["priority"] == 10


class TestAIOrchestorRouting:
    """Capability-based request routing."""

    def test_route_request_success(self):
        svc = AIOrchestorService()
        svc.register_model(
            TENANT, "router-model", "llm", "openai",
            capabilities=["text-generation"],
        )
        result = svc.route_request(TENANT, "text-generation", {"prompt": "hello"})
        assert result["status"] == "success"
        assert result["model_name"] == "router-model"
        assert result["capability"] == "text-generation"

    def test_route_request_no_model(self):
        svc = AIOrchestorService()
        result = svc.route_request(TENANT, "nonexistent-cap")
        assert result["status"] == "no_model"

    def test_route_request_prefers_higher_priority(self):
        svc = AIOrchestorService()
        svc.register_model(TENANT, "low-prio", "llm", "local", capabilities=["qa"], priority=8)
        svc.register_model(TENANT, "high-prio", "llm", "openai", capabilities=["qa"], priority=1)
        result = svc.route_request(TENANT, "qa")
        assert result["model_name"] == "high-prio"

    def test_route_request_skips_disabled_models(self):
        svc = AIOrchestorService()
        m = svc.register_model(TENANT, "disabled-m", "llm", "local", capabilities=["gen"], priority=1)
        svc.update_model(m["id"], enabled=False)
        svc.register_model(TENANT, "enabled-m", "llm", "local", capabilities=["gen"], priority=5)
        result = svc.route_request(TENANT, "gen")
        assert result["model_name"] == "enabled-m"

    def test_route_request_updates_metrics(self):
        svc = AIOrchestorService()
        m = svc.register_model(TENANT, "metric-m", "llm", "local", capabilities=["x"])
        svc.route_request(TENANT, "x")
        svc.route_request(TENANT, "x")
        updated = svc.get_model(m["id"])
        assert updated["total_requests"] == 2
        assert updated["successful_requests"] == 2

    def test_route_history(self):
        svc = AIOrchestorService()
        svc.register_model(TENANT, "hist-m", "llm", "local", capabilities=["h"])
        svc.route_request(TENANT, "h")
        history = svc.get_route_history(TENANT)
        assert len(history) == 1
        assert history[0]["capability"] == "h"


class TestAIOrchestorStats:
    """Statistics reporting."""

    def test_get_stats_empty(self):
        svc = AIOrchestorService()
        stats = svc.get_stats(TENANT)
        assert stats["total_models"] == 0
        assert stats["total_requests"] == 0

    def test_get_stats_with_models(self):
        svc = AIOrchestorService()
        svc.register_model(TENANT, "s1", "llm", "openai", capabilities=["a", "b"])
        svc.register_model(TENANT, "s2", "vision", "google", capabilities=["c"])
        svc.route_request(TENANT, "a")
        stats = svc.get_stats(TENANT)
        assert stats["total_models"] == 2
        assert stats["active_models"] == 2
        assert stats["by_type"]["llm"] == 1
        assert stats["by_type"]["vision"] == 1
        assert stats["by_provider"]["openai"] == 1
        assert stats["total_capabilities"] == 3
        assert stats["total_requests"] == 1
        assert stats["successful_requests"] == 1


# ---------------------------------------------------------------------------
# NLPolicyService
# ---------------------------------------------------------------------------

class TestNLPolicyBasic:
    """Create, list, approve, and reject NL policies."""

    def test_create_nl_policy(self):
        svc = NLPolicyService()
        policy = svc.create_nl_policy(TENANT, "Block all traffic from Russia")
        assert policy["natural_language"] == "Block all traffic from Russia"
        assert policy["status"] == "pending_review"
        assert len(policy["parsed_rules"]) >= 1
        assert policy["parsed_rules"][0]["action"] == "block"

    def test_create_nl_policy_with_condition(self):
        svc = NLPolicyService()
        policy = svc.create_nl_policy(TENANT, "Deny access if user is unauthenticated")
        rules = policy["parsed_rules"]
        assert len(rules) >= 1
        assert rules[0]["action"] == "deny"
        assert "condition" in rules[0]

    def test_list_policies(self):
        svc = NLPolicyService()
        svc.create_nl_policy(TENANT, "Allow internal traffic")
        svc.create_nl_policy(TENANT, "Block external SSH")
        policies = svc.list_policies(TENANT)
        assert len(policies) == 2

    def test_list_policies_empty(self):
        svc = NLPolicyService()
        assert svc.list_policies("nobody") == []

    def test_approve_policy(self):
        svc = NLPolicyService()
        policy = svc.create_nl_policy(TENANT, "Allow HTTPS from web to api")
        approved = svc.approve_policy(policy["id"], "admin-user")
        assert approved is not None
        assert approved["status"] == "approved"
        assert approved["approved_by"] == "admin-user"

    def test_reject_policy(self):
        svc = NLPolicyService()
        policy = svc.create_nl_policy(TENANT, "Require MFA when logging in")
        rejected = svc.reject_policy(policy["id"])
        assert rejected is not None
        assert rejected["status"] == "rejected"

    def test_approve_nonexistent_policy(self):
        svc = NLPolicyService()
        assert svc.approve_policy("no-such-id", "admin") is None

    def test_reject_nonexistent_policy(self):
        svc = NLPolicyService()
        assert svc.reject_policy("no-such-id") is None


class TestNLPolicyParsing:
    """Edge cases for the NL parsing engine."""

    def test_empty_text_zero_confidence(self):
        svc = NLPolicyService()
        policy = svc.create_nl_policy(TENANT, "   ")
        assert policy["confidence_score"] == 0.0
        assert policy["parsed_rules"] == []

    def test_no_action_keyword_no_rules(self):
        svc = NLPolicyService()
        policy = svc.create_nl_policy(TENANT, "The quick brown fox jumps over the lazy dog")
        assert policy["parsed_rules"] == []

    def test_multiple_sentences_multiple_rules(self):
        svc = NLPolicyService()
        policy = svc.create_nl_policy(
            TENANT,
            "Block traffic from Russia. Allow traffic from USA.",
        )
        rules = policy["parsed_rules"]
        assert len(rules) == 2
        actions = {r["action"] for r in rules}
        assert actions == {"block", "allow"}

    def test_direction_keywords_extracted(self):
        svc = NLPolicyService()
        policy = svc.create_nl_policy(TENANT, "Allow HTTPS from web-tier to api-tier")
        rules = policy["parsed_rules"]
        assert len(rules) >= 1
        assert "from" in rules[0]
        assert "to" in rules[0]


class TestNLPolicyStats:
    """Statistics reporting."""

    def test_get_stats(self):
        svc = NLPolicyService()
        p1 = svc.create_nl_policy(TENANT, "Block SSH")
        svc.create_nl_policy(TENANT, "Allow HTTPS")
        svc.approve_policy(p1["id"], "admin")
        stats = svc.get_stats(TENANT)
        assert stats["total"] == 2
        assert stats["by_status"]["approved"] == 1
        assert stats["by_status"]["pending_review"] == 1

    def test_get_stats_empty(self):
        svc = NLPolicyService()
        stats = svc.get_stats(TENANT)
        assert stats["total"] == 0
        assert stats["avg_confidence"] == 0.0


# ---------------------------------------------------------------------------
# IncidentCommanderService
# ---------------------------------------------------------------------------

class TestIncidentCommanderBasic:
    """Declare incidents, add updates, and list."""

    def test_declare_incident(self):
        svc = IncidentCommanderService()
        inc = svc.declare_incident(TENANT, "DB Outage", "critical", "Database unreachable")
        assert inc["title"] == "DB Outage"
        assert inc["severity"] == "critical"
        assert inc["status"] == "declared"
        assert inc["commander_ai"] == "sentinel-alpha"
        assert len(inc["timeline"]) == 1

    def test_declare_multiple_incidents_round_robin(self):
        svc = IncidentCommanderService()
        i1 = svc.declare_incident(TENANT, "Inc 1", "high")
        i2 = svc.declare_incident(TENANT, "Inc 2", "medium")
        i3 = svc.declare_incident(TENANT, "Inc 3", "low")
        assert i1["commander_ai"] == "sentinel-alpha"
        assert i2["commander_ai"] == "sentinel-bravo"
        assert i3["commander_ai"] == "sentinel-charlie"

    def test_add_update_changes_status(self):
        svc = IncidentCommanderService()
        inc = svc.declare_incident(TENANT, "Net Issue", "high")
        updated = svc.add_update(inc["id"], "Started investigation", status="investigating")
        assert updated is not None
        assert updated["status"] == "investigating"
        assert len(updated["timeline"]) == 2

    def test_add_update_text_only(self):
        svc = IncidentCommanderService()
        inc = svc.declare_incident(TENANT, "Test", "low")
        updated = svc.add_update(inc["id"], "Just a note")
        assert updated is not None
        assert updated["status"] == "declared"  # unchanged
        assert len(updated["timeline"]) == 2

    def test_resolve_incident_computes_mttr(self):
        svc = IncidentCommanderService()
        inc = svc.declare_incident(TENANT, "Resolved Quick", "medium")
        resolved = svc.add_update(inc["id"], "Fixed the root cause", status="resolved")
        assert resolved is not None
        assert resolved["status"] == "resolved"
        assert resolved["resolved_at"] is not None
        assert resolved["mttr_seconds"] is not None
        assert resolved["mttr_seconds"] >= 0.0

    def test_add_update_nonexistent(self):
        svc = IncidentCommanderService()
        assert svc.add_update("no-id", "text") is None

    def test_list_incidents(self):
        svc = IncidentCommanderService()
        svc.declare_incident(TENANT, "A", "high")
        svc.declare_incident(TENANT, "B", "low")
        incidents = svc.list_incidents(TENANT)
        assert len(incidents) == 2

    def test_list_incidents_empty_tenant(self):
        svc = IncidentCommanderService()
        assert svc.list_incidents("empty-tenant") == []

    def test_declare_with_related_ids(self):
        svc = IncidentCommanderService()
        inc = svc.declare_incident(TENANT, "Related", "high", related_ids=["prev-1", "prev-2"])
        assert inc["related_incident_ids"] == ["prev-1", "prev-2"]


class TestIncidentCommanderStats:
    """Statistics reporting."""

    def test_get_stats(self):
        svc = IncidentCommanderService()
        inc = svc.declare_incident(TENANT, "S1", "critical")
        svc.declare_incident(TENANT, "S2", "high")
        svc.add_update(inc["id"], "Resolved", status="resolved")
        stats = svc.get_stats(TENANT)
        assert stats["total"] == 2
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_severity"]["high"] == 1
        assert stats["by_status"]["resolved"] == 1
        assert stats["by_status"]["declared"] == 1
        assert stats["avg_mttr_seconds"] is not None

    def test_get_stats_no_resolved(self):
        svc = IncidentCommanderService()
        svc.declare_incident(TENANT, "Open", "low")
        stats = svc.get_stats(TENANT)
        assert stats["avg_mttr_seconds"] is None


# ---------------------------------------------------------------------------
# ThreatSharingService
# ---------------------------------------------------------------------------

class TestThreatSharingBasic:
    """Share, consume, and list indicators."""

    def test_share_indicator(self):
        svc = ThreatSharingService()
        ind = svc.share_indicator(TENANT, "ip", "192.168.1.100", severity="high")
        assert ind["source_tenant"] == TENANT
        assert ind["indicator_type"] == "ip"
        assert ind["indicator_value"] == "192.168.1.100"
        assert ind["severity"] == "high"
        assert ind["trust_score"] == 0.8

    def test_list_shared(self):
        svc = ThreatSharingService()
        svc.share_indicator(TENANT, "domain", "evil.com")
        svc.share_indicator(TENANT, "hash", "abc123def456")
        shared = svc.list_shared(TENANT)
        assert len(shared) == 2

    def test_list_shared_empty(self):
        svc = ThreatSharingService()
        assert svc.list_shared("nobody") == []

    def test_consume_indicator(self):
        svc = ThreatSharingService()
        ind = svc.share_indicator(TENANT, "url", "https://bad.example.com")
        consumed = svc.consume_indicator(ind["id"], "other-tenant")
        assert consumed is not None
        assert "other-tenant" in consumed["consumed_by"]

    def test_consume_indicator_idempotent(self):
        svc = ThreatSharingService()
        ind = svc.share_indicator(TENANT, "ip", "10.0.0.1")
        svc.consume_indicator(ind["id"], "consumer-a")
        svc.consume_indicator(ind["id"], "consumer-a")
        result = svc.consume_indicator(ind["id"], "consumer-a")
        assert result["consumed_by"].count("consumer-a") == 1

    def test_consume_nonexistent_indicator(self):
        svc = ThreatSharingService()
        assert svc.consume_indicator("ghost-id", "consumer") is None


class TestThreatSharingFeed:
    """Cross-tenant feed filtering."""

    def test_feed_excludes_own_indicators(self):
        svc = ThreatSharingService()
        svc.share_indicator(TENANT, "ip", "1.1.1.1")
        svc.share_indicator("other-tenant", "ip", "2.2.2.2")
        feed = svc.get_feed(TENANT)
        assert len(feed) == 1
        assert feed[0]["indicator_value"] == "2.2.2.2"

    def test_feed_filters_by_min_trust(self):
        svc = ThreatSharingService()
        # Default trust is 0.8
        svc.share_indicator("t-a", "ip", "3.3.3.3")
        feed_high = svc.get_feed(TENANT, min_trust=0.9)
        feed_low = svc.get_feed(TENANT, min_trust=0.5)
        assert len(feed_high) == 0
        assert len(feed_low) == 1

    def test_feed_empty_when_no_others(self):
        svc = ThreatSharingService()
        svc.share_indicator(TENANT, "domain", "only-mine.com")
        assert svc.get_feed(TENANT) == []


class TestThreatSharingStats:
    """Statistics reporting."""

    def test_get_stats(self):
        svc = ThreatSharingService()
        ind = svc.share_indicator(TENANT, "ip", "4.4.4.4")
        svc.share_indicator(TENANT, "domain", "bad.org")
        svc.consume_indicator(ind["id"], "consumer-x")
        stats = svc.get_stats(TENANT)
        assert stats["total_shared"] == 2
        assert stats["total_consumed"] == 1
        assert stats["by_type"]["ip"] == 1
        assert stats["by_type"]["domain"] == 1
        assert stats["avg_trust"] == 0.8


# ---------------------------------------------------------------------------
# DeceptionService
# ---------------------------------------------------------------------------

class TestDeceptionBasic:
    """Deploy, list, get, activate, and deactivate tokens."""

    def test_deploy_token(self):
        svc = DeceptionService()
        token = svc.deploy_token(
            TENANT, "db-creds", "honey_credential",
            decoy_value="admin:P@ssw0rd",
            placement="/etc/db.conf",
        )
        assert token["name"] == "db-creds"
        assert token["token_type"] == "honey_credential"
        assert token["active"] is True
        assert token["triggered"] is False

    def test_deploy_token_auto_decoy(self):
        svc = DeceptionService()
        token = svc.deploy_token(TENANT, "auto", "honey_api_key")
        assert token["decoy_value"].startswith("ak_")

    def test_get_token(self):
        svc = DeceptionService()
        created = svc.deploy_token(TENANT, "findme", "canary_dns")
        fetched = svc.get_token(created["id"])
        assert fetched is not None
        assert fetched["name"] == "findme"

    def test_get_token_not_found(self):
        svc = DeceptionService()
        assert svc.get_token("nope") is None

    def test_list_tokens(self):
        svc = DeceptionService()
        svc.deploy_token(TENANT, "t1", "honey_file")
        svc.deploy_token(TENANT, "t2", "canary_url")
        tokens = svc.list_tokens(TENANT)
        assert len(tokens) == 2

    def test_list_tokens_filter_by_type(self):
        svc = DeceptionService()
        svc.deploy_token(TENANT, "t1", "honey_file")
        svc.deploy_token(TENANT, "t2", "canary_url")
        tokens = svc.list_tokens(TENANT, token_type="honey_file")
        assert len(tokens) == 1
        assert tokens[0]["name"] == "t1"

    def test_deactivate_token(self):
        svc = DeceptionService()
        token = svc.deploy_token(TENANT, "deact", "honey_credential", decoy_value="secret123")
        result = svc.deactivate_token(token["id"])
        assert result is not None
        assert result["active"] is False

    def test_activate_token(self):
        svc = DeceptionService()
        token = svc.deploy_token(TENANT, "react", "honey_token", decoy_value="tok-123")
        svc.deactivate_token(token["id"])
        result = svc.activate_token(token["id"])
        assert result is not None
        assert result["active"] is True

    def test_deactivate_not_found(self):
        svc = DeceptionService()
        assert svc.deactivate_token("no-id") is None


class TestDeceptionTriggers:
    """Trigger detection and recording."""

    def test_check_trigger_match(self):
        svc = DeceptionService()
        svc.deploy_token(TENANT, "trap", "honey_credential", decoy_value="trap-cred")
        result = svc.check_trigger("trap-cred")
        assert result["triggered"] is True
        assert result["token_name"] == "trap"

    def test_check_trigger_no_match(self):
        svc = DeceptionService()
        result = svc.check_trigger("random-value")
        assert result["triggered"] is False
        assert result["token_id"] is None

    def test_check_trigger_inactive_token(self):
        svc = DeceptionService()
        token = svc.deploy_token(TENANT, "dead", "honey_file", decoy_value="/tmp/bait")
        svc.deactivate_token(token["id"])
        result = svc.check_trigger("/tmp/bait")
        assert result["triggered"] is False

    def test_record_trigger(self):
        svc = DeceptionService()
        token = svc.deploy_token(TENANT, "rec", "canary_dns", decoy_value="bait.dns")
        result = svc.record_trigger(token["id"], source_ip="10.0.0.99")
        assert result is not None
        assert result["triggered"] is True
        assert result["trigger_count"] == 1
        assert len(result["triggers"]) == 1
        assert result["triggers"][0]["source_ip"] == "10.0.0.99"

    def test_record_trigger_increments_count(self):
        svc = DeceptionService()
        token = svc.deploy_token(TENANT, "multi", "honey_token", decoy_value="mt-val")
        svc.record_trigger(token["id"], source_ip="1.1.1.1")
        result = svc.record_trigger(token["id"], source_ip="2.2.2.2")
        assert result["trigger_count"] == 2

    def test_record_trigger_not_found(self):
        svc = DeceptionService()
        assert svc.record_trigger("no-such-token") is None


class TestDeceptionStats:
    """Statistics reporting."""

    def test_get_stats(self):
        svc = DeceptionService()
        t = svc.deploy_token(TENANT, "s1", "honey_credential", decoy_value="sc1")
        svc.deploy_token(TENANT, "s2", "canary_url", decoy_value="sc2")
        svc.record_trigger(t["id"], source_ip="5.5.5.5")
        stats = svc.get_stats(TENANT)
        assert stats["total_tokens"] == 2
        assert stats["active_tokens"] == 2
        assert stats["triggered_tokens"] == 1
        assert stats["total_triggers"] == 1
        assert stats["by_type"]["honey_credential"] == 1
        assert stats["by_type"]["canary_url"] == 1


# ---------------------------------------------------------------------------
# ForensicsService
# ---------------------------------------------------------------------------

class TestForensicsCaseBasic:
    """Create, get, list, update, and close cases."""

    def test_create_case(self):
        svc = ForensicsService()
        case = svc.create_case(TENANT, "Breach Investigation", severity="critical")
        assert case["title"] == "Breach Investigation"
        assert case["status"] == "open"
        assert case["severity"] == "critical"

    def test_get_case(self):
        svc = ForensicsService()
        created = svc.create_case(TENANT, "Findable Case")
        fetched = svc.get_case(created["id"])
        assert fetched is not None
        assert fetched["title"] == "Findable Case"

    def test_get_case_not_found(self):
        svc = ForensicsService()
        assert svc.get_case("nope") is None

    def test_list_cases(self):
        svc = ForensicsService()
        svc.create_case(TENANT, "C1")
        svc.create_case(TENANT, "C2")
        cases = svc.list_cases(TENANT)
        assert len(cases) == 2

    def test_list_cases_filter_by_status(self):
        svc = ForensicsService()
        c1 = svc.create_case(TENANT, "Open Case")
        svc.close_case(c1["id"])
        svc.create_case(TENANT, "Still Open")
        open_cases = svc.list_cases(TENANT, status="open")
        assert len(open_cases) == 1
        assert open_cases[0]["title"] == "Still Open"

    def test_update_case(self):
        svc = ForensicsService()
        case = svc.create_case(TENANT, "Updateable")
        updated = svc.update_case(
            case["id"],
            status="investigating",
            lead_investigator="alice",
            findings=["Found malware"],
        )
        assert updated is not None
        assert updated["status"] == "investigating"
        assert updated["lead_investigator"] == "alice"
        assert "Found malware" in updated["findings"]

    def test_update_case_not_found(self):
        svc = ForensicsService()
        assert svc.update_case("nope") is None

    def test_close_case(self):
        svc = ForensicsService()
        case = svc.create_case(TENANT, "Closeable")
        closed = svc.close_case(case["id"], final_findings=["Root cause identified"])
        assert closed is not None
        assert closed["status"] == "closed"
        assert closed["closed_at"] is not None
        assert "Root cause identified" in closed["findings"]

    def test_close_case_not_found(self):
        svc = ForensicsService()
        assert svc.close_case("ghost") is None


class TestForensicsEvidence:
    """Evidence collection and chain of custody."""

    def test_add_evidence(self):
        svc = ForensicsService()
        case = svc.create_case(TENANT, "Evidence Case")
        evidence = svc.add_evidence(
            case["id"],
            evidence_type="log",
            source="firewall",
            description="Firewall access logs",
            data_content="log line 1\nlog line 2",
        )
        assert evidence is not None
        assert evidence["evidence_type"] == "log"
        assert evidence["source"] == "firewall"
        expected_hash = hashlib.sha256("log line 1\nlog line 2".encode()).hexdigest()
        assert evidence["hash_sha256"] == expected_hash

    def test_add_evidence_chain_of_custody(self):
        svc = ForensicsService()
        case = svc.create_case(TENANT, "CoC Case")
        evidence = svc.add_evidence(case["id"], "pcap", source="switch-01", data_content="data")
        assert len(evidence["chain_of_custody"]) == 1
        assert evidence["chain_of_custody"][0]["action"] == "collected"

    def test_add_evidence_to_nonexistent_case(self):
        svc = ForensicsService()
        assert svc.add_evidence("no-case", "log") is None

    def test_get_evidence(self):
        svc = ForensicsService()
        case = svc.create_case(TENANT, "GetEv")
        ev = svc.add_evidence(case["id"], "memory_dump", source="host-1")
        fetched = svc.get_evidence(ev["id"])
        assert fetched is not None
        assert fetched["evidence_type"] == "memory_dump"

    def test_list_evidence(self):
        svc = ForensicsService()
        case = svc.create_case(TENANT, "ListEv")
        svc.add_evidence(case["id"], "log", source="src1")
        svc.add_evidence(case["id"], "pcap", source="src2")
        evidence_list = svc.list_evidence(case["id"])
        assert len(evidence_list) == 2

    def test_list_evidence_nonexistent_case(self):
        svc = ForensicsService()
        assert svc.list_evidence("no-case") == []

    def test_add_custody_entry(self):
        svc = ForensicsService()
        case = svc.create_case(TENANT, "Custody")
        ev = svc.add_evidence(case["id"], "disk_image", source="server-1")
        updated = svc.add_custody_entry(ev["id"], "transferred", by="bob", notes="To lab")
        assert updated is not None
        assert len(updated["chain_of_custody"]) == 2
        assert updated["chain_of_custody"][1]["action"] == "transferred"

    def test_add_custody_entry_not_found(self):
        svc = ForensicsService()
        assert svc.add_custody_entry("no-ev", "action", by="x") is None


class TestForensicsTimeline:
    """Timeline reconstruction."""

    def test_build_timeline(self):
        svc = ForensicsService()
        case = svc.create_case(TENANT, "Timeline Case")
        svc.add_evidence(case["id"], "log", source="fw", description="FW log")
        svc.add_evidence(case["id"], "pcap", source="switch", description="Network capture")
        timeline = svc.build_timeline(case["id"])
        assert len(timeline) == 2
        for event in timeline:
            assert "timestamp" in event
            assert "evidence_type" in event

    def test_build_timeline_nonexistent_case(self):
        svc = ForensicsService()
        assert svc.build_timeline("no-case") == []


class TestForensicsStats:
    """Statistics reporting."""

    def test_get_stats(self):
        svc = ForensicsService()
        c = svc.create_case(TENANT, "St1", severity="high")
        svc.create_case(TENANT, "St2", severity="low")
        svc.add_evidence(c["id"], "log")
        svc.close_case(c["id"])
        stats = svc.get_stats(TENANT)
        assert stats["total_cases"] == 2
        assert stats["open_cases"] == 1
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["low"] == 1
        assert stats["total_evidence_items"] == 1


# ---------------------------------------------------------------------------
# ComplianceCodeService
# ---------------------------------------------------------------------------

class TestComplianceRuleBasic:
    """Create, list, get, and toggle compliance rules."""

    def test_create_rule(self):
        svc = ComplianceCodeService()
        rule = svc.create_rule(TENANT, "HIPAA", "164.312(a)(1)", "Access Control")
        assert rule["framework"] == "HIPAA"
        assert rule["control_id"] == "164.312(a)(1)"
        assert rule["enabled"] is True

    def test_create_rule_unsupported_framework(self):
        svc = ComplianceCodeService()
        result = svc.create_rule(TENANT, "FAKE-FW", "1.1", "Bad Rule")
        assert "error" in result

    def test_get_rule(self):
        svc = ComplianceCodeService()
        created = svc.create_rule(TENANT, "PCI-DSS", "3.4", "Encrypt PAN")
        fetched = svc.get_rule(created["id"])
        assert fetched is not None
        assert fetched["title"] == "Encrypt PAN"

    def test_get_rule_not_found(self):
        svc = ComplianceCodeService()
        assert svc.get_rule("nope") is None

    def test_list_rules(self):
        svc = ComplianceCodeService()
        svc.create_rule(TENANT, "GDPR", "Art5", "Data Minimization")
        svc.create_rule(TENANT, "SOC2", "CC6.1", "Logical Access")
        rules = svc.list_rules(TENANT)
        assert len(rules) == 2

    def test_list_rules_filter_by_framework(self):
        svc = ComplianceCodeService()
        svc.create_rule(TENANT, "GDPR", "Art5", "DM")
        svc.create_rule(TENANT, "HIPAA", "164", "AC")
        rules = svc.list_rules(TENANT, framework="GDPR")
        assert len(rules) == 1
        assert rules[0]["framework"] == "GDPR"

    def test_toggle_rule(self):
        svc = ComplianceCodeService()
        rule = svc.create_rule(TENANT, "NIST", "AC-1", "Access Policy")
        toggled = svc.toggle_rule(rule["id"], enabled=False)
        assert toggled is not None
        assert toggled["enabled"] is False

    def test_toggle_rule_not_found(self):
        svc = ComplianceCodeService()
        assert svc.toggle_rule("no-id", True) is None


class TestComplianceChecks:
    """Run individual checks and framework audits."""

    def test_run_check_policy_pass(self):
        svc = ComplianceCodeService()
        rule = svc.create_rule(
            TENANT, "HIPAA", "164.312", "MFA Required",
            check_type="policy",
            check_config={"required_field": "mfa_enabled", "expected_value": "True"},
        )
        result = svc.run_check(rule["id"], system_state={"mfa_enabled": "True"})
        assert result["result"] == "pass"

    def test_run_check_policy_fail(self):
        svc = ComplianceCodeService()
        rule = svc.create_rule(
            TENANT, "HIPAA", "164.312", "MFA Required",
            check_type="policy",
            check_config={"required_field": "mfa_enabled", "expected_value": "True"},
        )
        result = svc.run_check(rule["id"], system_state={"mfa_enabled": "False"})
        assert result["result"] == "fail"

    def test_run_check_encryption_pass(self):
        svc = ComplianceCodeService()
        rule = svc.create_rule(
            TENANT, "PCI-DSS", "3.4", "Encryption at rest",
            check_type="encryption",
            check_config={"require_at_rest": True, "require_in_transit": True},
        )
        result = svc.run_check(rule["id"], system_state={
            "encryption_at_rest": True, "encryption_in_transit": True,
        })
        assert result["result"] == "pass"

    def test_run_check_encryption_fail(self):
        svc = ComplianceCodeService()
        rule = svc.create_rule(
            TENANT, "PCI-DSS", "3.4", "Encryption at rest",
            check_type="encryption",
            check_config={"require_at_rest": True},
        )
        result = svc.run_check(rule["id"], system_state={"encryption_at_rest": False})
        assert result["result"] == "fail"

    def test_run_check_network_pass(self):
        svc = ComplianceCodeService()
        rule = svc.create_rule(
            TENANT, "CIS", "9.1", "Block Telnet",
            check_type="network",
            check_config={"blocked_ports": [23, 21]},
        )
        result = svc.run_check(rule["id"], system_state={"open_ports": [80, 443]})
        assert result["result"] == "pass"

    def test_run_check_network_fail(self):
        svc = ComplianceCodeService()
        rule = svc.create_rule(
            TENANT, "CIS", "9.1", "Block Telnet",
            check_type="network",
            check_config={"blocked_ports": [23]},
        )
        result = svc.run_check(rule["id"], system_state={"open_ports": [23, 80]})
        assert result["result"] == "fail"

    def test_run_check_disabled_rule(self):
        svc = ComplianceCodeService()
        rule = svc.create_rule(TENANT, "NIST", "AC-1", "Disabled Check", check_type="policy")
        svc.toggle_rule(rule["id"], enabled=False)
        result = svc.run_check(rule["id"])
        assert "error" in result

    def test_run_check_rule_not_found(self):
        svc = ComplianceCodeService()
        result = svc.run_check("nonexistent")
        assert "error" in result

    def test_run_framework_audit(self):
        svc = ComplianceCodeService()
        svc.create_rule(
            TENANT, "GDPR", "Art5", "Minimization",
            check_type="policy",
            check_config={"required_field": "data_minimized", "expected_value": "yes"},
        )
        svc.create_rule(
            TENANT, "GDPR", "Art32", "Encryption",
            check_type="encryption",
            check_config={"require_at_rest": True},
        )
        audit = svc.run_framework_audit(
            TENANT, "GDPR",
            system_state={"data_minimized": "yes", "encryption_at_rest": True},
        )
        assert audit["framework"] == "GDPR"
        assert audit["total_rules"] == 2
        assert audit["summary"]["pass"] == 2
        assert audit["compliance_percentage"] == 100.0

    def test_run_framework_audit_empty(self):
        svc = ComplianceCodeService()
        audit = svc.run_framework_audit(TENANT, "NIST")
        assert audit["total_rules"] == 0

    def test_compliance_report(self):
        svc = ComplianceCodeService()
        rule = svc.create_rule(
            TENANT, "SOC2", "CC6.1", "Access Control",
            check_type="access",
            check_config={"require_mfa": True},
        )
        svc.run_check(rule["id"], system_state={"mfa_enabled": True})
        report = svc.get_compliance_report(TENANT)
        assert report["total_rules"] == 1
        assert "SOC2" in report["frameworks"]


class TestComplianceStats:
    """Statistics reporting."""

    def test_get_stats(self):
        svc = ComplianceCodeService()
        rule = svc.create_rule(TENANT, "HIPAA", "164", "Test", check_type="policy",
                               check_config={"required_field": "x", "expected_value": "y"})
        svc.create_rule(TENANT, "GDPR", "Art5", "Test2")
        svc.run_check(rule["id"], system_state={"x": "y"})
        stats = svc.get_stats(TENANT)
        assert stats["total_rules"] == 2
        assert stats["enabled_rules"] == 2
        assert stats["by_framework"]["HIPAA"] == 1
        assert stats["by_framework"]["GDPR"] == 1
        assert stats["total_checks_run"] == 1
        assert stats["latest_results"]["pass"] == 1


# ---------------------------------------------------------------------------
# EvolvingRulesService
# ---------------------------------------------------------------------------

class TestEvolvingRulesBasic:
    """Create, list, get, and toggle detection rules."""

    def test_create_rule(self):
        svc = EvolvingRulesService()
        rule = svc.create_rule(TENANT, "SSH Brute Force", category="network", severity="high")
        assert rule["name"] == "SSH Brute Force"
        assert rule["category"] == "network"
        assert rule["generation"] == 1
        assert rule["enabled"] is True
        assert rule["fitness_score"] == 0.5

    def test_get_rule(self):
        svc = EvolvingRulesService()
        created = svc.create_rule(TENANT, "Lateral Move")
        fetched = svc.get_rule(created["id"])
        assert fetched is not None
        assert fetched["name"] == "Lateral Move"

    def test_get_rule_not_found(self):
        svc = EvolvingRulesService()
        assert svc.get_rule("nope") is None

    def test_list_rules(self):
        svc = EvolvingRulesService()
        svc.create_rule(TENANT, "R1", category="network")
        svc.create_rule(TENANT, "R2", category="endpoint")
        rules = svc.list_rules(TENANT)
        assert len(rules) == 2

    def test_list_rules_filter_by_category(self):
        svc = EvolvingRulesService()
        svc.create_rule(TENANT, "R1", category="network")
        svc.create_rule(TENANT, "R2", category="endpoint")
        rules = svc.list_rules(TENANT, category="network")
        assert len(rules) == 1
        assert rules[0]["name"] == "R1"

    def test_list_rules_enabled_only(self):
        svc = EvolvingRulesService()
        r = svc.create_rule(TENANT, "Disabled One")
        svc.create_rule(TENANT, "Enabled One")
        svc.toggle_rule(r["id"], enabled=False)
        rules = svc.list_rules(TENANT, enabled_only=True)
        assert len(rules) == 1
        assert rules[0]["name"] == "Enabled One"

    def test_toggle_rule(self):
        svc = EvolvingRulesService()
        rule = svc.create_rule(TENANT, "Togglable")
        toggled = svc.toggle_rule(rule["id"], enabled=False)
        assert toggled is not None
        assert toggled["enabled"] is False

    def test_toggle_rule_not_found(self):
        svc = EvolvingRulesService()
        assert svc.toggle_rule("no-id", True) is None


class TestEvolvingRulesEvaluation:
    """Evaluate rules against events."""

    def test_evaluate_rule_match(self):
        svc = EvolvingRulesService()
        rule = svc.create_rule(
            TENANT, "High Traffic",
            conditions={"bytes": {"operator": "gt", "value": 1000}},
            threshold=0.5,
        )
        result = svc.evaluate_rule(rule["id"], {"bytes": 5000})
        assert result["match"] is True
        assert result["score"] >= 0.5

    def test_evaluate_rule_no_match(self):
        svc = EvolvingRulesService()
        rule = svc.create_rule(
            TENANT, "High Traffic",
            conditions={"bytes": {"operator": "gt", "value": 1000}},
            threshold=0.5,
        )
        result = svc.evaluate_rule(rule["id"], {"bytes": 500})
        assert result["match"] is False

    def test_evaluate_rule_disabled(self):
        svc = EvolvingRulesService()
        rule = svc.create_rule(TENANT, "Off")
        svc.toggle_rule(rule["id"], enabled=False)
        result = svc.evaluate_rule(rule["id"], {"x": 1})
        assert result["match"] is False
        assert result["reason"] == "Rule is disabled"

    def test_evaluate_rule_not_found(self):
        svc = EvolvingRulesService()
        result = svc.evaluate_rule("nope", {})
        assert "error" in result

    def test_evaluate_multiple_conditions(self):
        svc = EvolvingRulesService()
        rule = svc.create_rule(
            TENANT, "Multi",
            conditions={
                "src_port": {"operator": "eq", "value": "22"},
                "action": {"operator": "eq", "value": "block"},
            },
            threshold=1.0,
        )
        result = svc.evaluate_rule(rule["id"], {"src_port": "22", "action": "block"})
        assert result["match"] is True
        assert result["score"] == 1.0

    def test_evaluate_contains_operator(self):
        svc = EvolvingRulesService()
        rule = svc.create_rule(
            TENANT, "Path Check",
            conditions={"path": {"operator": "contains", "value": "admin"}},
            threshold=0.5,
        )
        result = svc.evaluate_rule(rule["id"], {"path": "/api/admin/settings"})
        assert result["match"] is True


class TestEvolvingRulesOutcomes:
    """Record outcomes and observe metric updates."""

    def test_record_true_positive(self):
        svc = EvolvingRulesService()
        rule = svc.create_rule(TENANT, "TP Test")
        outcome = svc.record_outcome(rule["id"], "true_positive")
        assert outcome is not None
        assert outcome["outcome"] == "true_positive"
        updated = svc.get_rule(rule["id"])
        assert updated["true_positives"] == 1
        assert updated["precision"] == 1.0

    def test_record_false_positive(self):
        svc = EvolvingRulesService()
        rule = svc.create_rule(TENANT, "FP Test")
        svc.record_outcome(rule["id"], "false_positive")
        updated = svc.get_rule(rule["id"])
        assert updated["false_positives"] == 1
        assert updated["precision"] == 0.0

    def test_record_invalid_outcome(self):
        svc = EvolvingRulesService()
        rule = svc.create_rule(TENANT, "Bad Outcome")
        assert svc.record_outcome(rule["id"], "invalid_type") is None

    def test_record_outcome_rule_not_found(self):
        svc = EvolvingRulesService()
        assert svc.record_outcome("no-rule", "true_positive") is None

    def test_precision_calculation(self):
        svc = EvolvingRulesService()
        rule = svc.create_rule(TENANT, "Precision")
        svc.record_outcome(rule["id"], "true_positive")
        svc.record_outcome(rule["id"], "true_positive")
        svc.record_outcome(rule["id"], "false_positive")
        updated = svc.get_rule(rule["id"])
        # precision = 2 / (2 + 1) = 0.667
        assert updated["precision"] == 0.667


class TestEvolvingRulesEvolution:
    """Evolve underperforming rules into improved generations."""

    def test_evolve_creates_child(self):
        svc = EvolvingRulesService()
        rule = svc.create_rule(
            TENANT, "Evolve Me",
            conditions={"x": {"operator": "gt", "value": 10}},
            threshold=0.5,
        )
        # Record enough outcomes to trigger evolution (>= min_evaluations with high FP)
        for _ in range(4):
            svc.record_outcome(rule["id"], "true_positive")
        for _ in range(7):
            svc.record_outcome(rule["id"], "false_positive")
        evolved = svc.evolve_rules(TENANT, min_evaluations=10, max_false_positive_rate=0.3)
        assert len(evolved) == 1
        child = evolved[0]
        assert child["generation"] == 2
        assert child["parent_id"] == rule["id"]
        assert "evolved" in child["tags"]
        # Parent should be disabled
        parent = svc.get_rule(rule["id"])
        assert parent["enabled"] is False

    def test_evolve_no_candidates(self):
        svc = EvolvingRulesService()
        svc.create_rule(TENANT, "Good Rule")
        evolved = svc.evolve_rules(TENANT)
        assert evolved == []

    def test_lineage_tracking(self):
        svc = EvolvingRulesService()
        r1 = svc.create_rule(TENANT, "Gen1", conditions={"x": {"operator": "gt", "value": 5}})
        r2 = svc.create_rule(TENANT, "Gen2", parent_id=r1["id"])
        r3 = svc.create_rule(TENANT, "Gen3", parent_id=r2["id"])
        assert r2["generation"] == 2
        assert r3["generation"] == 3
        lineage = svc.get_lineage(r3["id"])
        assert len(lineage) == 3
        assert lineage[0]["id"] == r1["id"]
        assert lineage[1]["id"] == r2["id"]
        assert lineage[2]["id"] == r3["id"]

    def test_lineage_not_found(self):
        svc = EvolvingRulesService()
        assert svc.get_lineage("nope") == []


class TestEvolvingRulesStats:
    """Statistics reporting."""

    def test_get_stats(self):
        svc = EvolvingRulesService()
        r = svc.create_rule(TENANT, "StatRule", category="network")
        svc.create_rule(TENANT, "StatRule2", category="endpoint")
        svc.record_outcome(r["id"], "true_positive")
        svc.record_outcome(r["id"], "false_positive")
        stats = svc.get_stats(TENANT)
        assert stats["total_rules"] == 2
        assert stats["active_rules"] == 2
        assert stats["by_category"]["network"] == 1
        assert stats["by_category"]["endpoint"] == 1
        assert stats["total_true_positives"] == 1
        assert stats["total_false_positives"] == 1
        assert stats["total_outcomes"] == 2

    def test_get_stats_empty(self):
        svc = EvolvingRulesService()
        stats = svc.get_stats(TENANT)
        assert stats["total_rules"] == 0
        assert stats["avg_fitness"] == 0.0
        assert stats["avg_precision"] == 0.0
