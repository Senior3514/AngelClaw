"""Tests for V6.0 Omniguard: Cloud Connector, CSPM, SaaS Shield, Hybrid Mesh."""

from __future__ import annotations

import pytest

from cloud.services.cloud_connector import CloudConnectorService
from cloud.services.cspm import CSPMService
from cloud.services.saas_shield import SaaSShieldService
from cloud.services.hybrid_mesh import HybridMeshService


TENANT = "test-tenant"


# ---------------------------------------------------------------------------
# CloudConnectorService
# ---------------------------------------------------------------------------


class TestCloudConnectorAdd:
    """Adding cloud connectors with various providers and configurations."""

    def test_add_aws_connector(self):
        svc = CloudConnectorService()
        result = svc.add_connector(TENANT, "aws", "my-aws", config={"account": "123"})
        assert result["cloud_provider"] == "aws"
        assert result["name"] == "my-aws"
        assert result["tenant_id"] == TENANT
        assert result["enabled"] is True
        assert result["health_status"] == "unknown"

    def test_add_azure_connector(self):
        svc = CloudConnectorService()
        result = svc.add_connector(TENANT, "azure", "my-azure")
        assert result["cloud_provider"] == "azure"
        assert result["name"] == "my-azure"

    def test_add_gcp_connector(self):
        svc = CloudConnectorService()
        result = svc.add_connector(TENANT, "gcp", "my-gcp", regions=["us-central1"])
        assert result["cloud_provider"] == "gcp"
        assert result["regions"] == ["us-central1"]

    def test_add_oci_connector(self):
        svc = CloudConnectorService()
        result = svc.add_connector(TENANT, "oci", "my-oci")
        assert result["cloud_provider"] == "oci"

    def test_add_alibaba_connector(self):
        svc = CloudConnectorService()
        result = svc.add_connector(TENANT, "alibaba", "my-alibaba")
        assert result["cloud_provider"] == "alibaba"

    @pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "oci", "alibaba"])
    def test_add_all_supported_providers(self, provider):
        svc = CloudConnectorService()
        result = svc.add_connector(TENANT, provider, f"conn-{provider}")
        assert result["cloud_provider"] == provider
        assert "error" not in result

    def test_add_unsupported_provider_returns_error(self):
        svc = CloudConnectorService()
        result = svc.add_connector(TENANT, "digitalocean", "my-do")
        assert "error" in result
        assert "Unsupported provider" in result["error"]

    @pytest.mark.parametrize("bad_provider", ["hetzner", "linode", "vultr", ""])
    def test_add_various_unsupported_providers(self, bad_provider):
        svc = CloudConnectorService()
        result = svc.add_connector(TENANT, bad_provider, f"conn-{bad_provider}")
        assert "error" in result

    def test_add_connector_case_insensitive_provider(self):
        svc = CloudConnectorService()
        result = svc.add_connector(TENANT, "AWS", "upper-aws")
        assert result["cloud_provider"] == "aws"

    def test_add_connector_with_multiple_regions(self):
        svc = CloudConnectorService()
        regions = ["us-east-1", "us-west-2", "eu-west-1"]
        result = svc.add_connector(TENANT, "aws", "multi-region", regions=regions)
        assert result["regions"] == regions

    def test_add_connector_default_empty_config(self):
        svc = CloudConnectorService()
        result = svc.add_connector(TENANT, "aws", "no-config")
        assert result["config"] == {}

    def test_add_connector_default_empty_regions(self):
        svc = CloudConnectorService()
        result = svc.add_connector(TENANT, "aws", "no-regions")
        assert result["regions"] == []

    def test_add_connector_has_unique_id(self):
        svc = CloudConnectorService()
        r1 = svc.add_connector(TENANT, "aws", "c1")
        r2 = svc.add_connector(TENANT, "aws", "c2")
        assert r1["id"] != r2["id"]

    def test_add_connector_resources_discovered_starts_zero(self):
        svc = CloudConnectorService()
        result = svc.add_connector(TENANT, "aws", "fresh")
        assert result["resources_discovered"] == 0
        assert result["sync_errors"] == 0


class TestCloudConnectorList:
    """Listing cloud connectors per tenant."""

    def test_list_empty(self):
        svc = CloudConnectorService()
        assert svc.list_connectors(TENANT) == []

    def test_list_after_adding(self):
        svc = CloudConnectorService()
        svc.add_connector(TENANT, "aws", "c1")
        svc.add_connector(TENANT, "azure", "c2")
        conns = svc.list_connectors(TENANT)
        assert len(conns) == 2

    def test_list_tenant_isolation(self):
        svc = CloudConnectorService()
        svc.add_connector("tenant-a", "aws", "a-conn")
        svc.add_connector("tenant-b", "gcp", "b-conn")
        assert len(svc.list_connectors("tenant-a")) == 1
        assert len(svc.list_connectors("tenant-b")) == 1
        assert svc.list_connectors("tenant-a")[0]["name"] == "a-conn"


class TestCloudConnectorTest:
    """Testing connector health checks."""

    def test_test_connector_success(self):
        svc = CloudConnectorService()
        conn = svc.add_connector(TENANT, "aws", "test-conn")
        result = svc.test_connector(conn["id"])
        assert result["health_status"] == "healthy"
        assert result["connector_id"] == conn["id"]
        assert "tested_at" in result

    def test_test_connector_not_found(self):
        svc = CloudConnectorService()
        result = svc.test_connector("nonexistent-id")
        assert "error" in result
        assert result["error"] == "Connector not found"

    def test_test_connector_updates_health(self):
        svc = CloudConnectorService()
        conn = svc.add_connector(TENANT, "aws", "health-check")
        assert conn["health_status"] == "unknown"
        svc.test_connector(conn["id"])
        updated = svc.list_connectors(TENANT)[0]
        assert updated["health_status"] == "healthy"


class TestCloudConnectorSync:
    """Sync resource discovery for connectors."""

    def test_sync_resources_basic(self):
        svc = CloudConnectorService()
        conn = svc.add_connector(TENANT, "aws", "sync-test", regions=["us-east-1"])
        result = svc.sync_resources(conn["id"])
        assert result["resources_discovered"] == 3  # 1 region * 3 resources
        assert result["total_resources"] == 3
        assert "synced_at" in result

    def test_sync_resources_multiple_regions(self):
        svc = CloudConnectorService()
        regions = ["us-east-1", "us-west-2"]
        conn = svc.add_connector(TENANT, "aws", "multi-sync", regions=regions)
        result = svc.sync_resources(conn["id"])
        assert result["resources_discovered"] == 6  # 2 regions * 3 resources

    def test_sync_resources_accumulates(self):
        svc = CloudConnectorService()
        conn = svc.add_connector(TENANT, "aws", "accum", regions=["us-east-1"])
        svc.sync_resources(conn["id"])
        result = svc.sync_resources(conn["id"])
        assert result["total_resources"] == 6  # 3 + 3

    def test_sync_not_found(self):
        svc = CloudConnectorService()
        result = svc.sync_resources("nonexistent")
        assert "error" in result

    def test_sync_disabled_connector(self):
        svc = CloudConnectorService()
        conn = svc.add_connector(TENANT, "aws", "disabled")
        svc._connectors[conn["id"]].enabled = False
        result = svc.sync_resources(conn["id"])
        assert "error" in result
        assert "disabled" in result["error"]

    def test_sync_no_regions_yields_zero_resources(self):
        svc = CloudConnectorService()
        conn = svc.add_connector(TENANT, "aws", "no-regions")
        result = svc.sync_resources(conn["id"])
        assert result["resources_discovered"] == 0


class TestCloudConnectorRemove:
    """Removing cloud connectors."""

    def test_remove_connector(self):
        svc = CloudConnectorService()
        conn = svc.add_connector(TENANT, "aws", "to-remove")
        result = svc.remove_connector(conn["id"])
        assert result is not None
        assert result["removed"] == conn["id"]
        assert svc.list_connectors(TENANT) == []

    def test_remove_nonexistent(self):
        svc = CloudConnectorService()
        result = svc.remove_connector("fake-id")
        assert result is None

    def test_remove_cleans_resources(self):
        svc = CloudConnectorService()
        conn = svc.add_connector(TENANT, "aws", "clean-up", regions=["us-east-1"])
        svc.sync_resources(conn["id"])
        assert len(svc._connector_resources[conn["id"]]) == 3
        svc.remove_connector(conn["id"])
        assert conn["id"] not in svc._connector_resources
        assert len(svc._resources) == 0


class TestCloudConnectorStats:
    """Statistics reporting for cloud connectors."""

    def test_stats_empty(self):
        svc = CloudConnectorService()
        stats = svc.get_stats(TENANT)
        assert stats["total_connectors"] == 0
        assert stats["enabled_connectors"] == 0
        assert stats["total_resources_discovered"] == 0

    def test_stats_after_adding(self):
        svc = CloudConnectorService()
        svc.add_connector(TENANT, "aws", "c1")
        svc.add_connector(TENANT, "azure", "c2")
        stats = svc.get_stats(TENANT)
        assert stats["total_connectors"] == 2
        assert stats["enabled_connectors"] == 2
        assert stats["by_provider"] == {"aws": 1, "azure": 1}
        assert stats["by_health"]["unknown"] == 2

    def test_stats_by_health_after_test(self):
        svc = CloudConnectorService()
        conn = svc.add_connector(TENANT, "aws", "tested")
        svc.test_connector(conn["id"])
        stats = svc.get_stats(TENANT)
        assert stats["by_health"]["healthy"] == 1

    def test_stats_resources_after_sync(self):
        svc = CloudConnectorService()
        conn = svc.add_connector(TENANT, "aws", "synced", regions=["us-east-1"])
        svc.sync_resources(conn["id"])
        stats = svc.get_stats(TENANT)
        assert stats["total_resources_discovered"] == 3


# ---------------------------------------------------------------------------
# CSPMService
# ---------------------------------------------------------------------------


class TestCSPMScan:
    """Running CSPM scans against cloud connectors."""

    def test_run_scan_basic(self):
        svc = CSPMService()
        result = svc.run_scan(TENANT, "conn-1")
        assert result["findings_count"] == 3
        assert result["benchmark"] == "cis"
        assert result["connector_id"] == "conn-1"
        assert "scan_id" in result
        assert "scanned_at" in result

    def test_run_scan_custom_benchmark(self):
        svc = CSPMService()
        result = svc.run_scan(TENANT, "conn-1", benchmark="nist")
        assert result["benchmark"] == "nist"

    def test_scan_creates_findings(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        findings = svc.get_findings(TENANT)
        assert len(findings) == 3

    def test_scan_records_in_history(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        svc.run_scan(TENANT, "conn-2")
        assert len(svc._scan_history[TENANT]) == 2

    def test_multiple_scans_accumulate_findings(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        svc.run_scan(TENANT, "conn-2")
        findings = svc.get_findings(TENANT)
        assert len(findings) == 6


class TestCSPMFindings:
    """Retrieving and filtering CSPM findings."""

    def test_get_findings_default_open(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        findings = svc.get_findings(TENANT)
        for f in findings:
            assert f["status"] == "open"

    def test_get_findings_filter_severity(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        critical = svc.get_findings(TENANT, severity="critical")
        assert len(critical) == 1
        assert critical[0]["severity"] == "critical"

    def test_get_findings_filter_high(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        high = svc.get_findings(TENANT, severity="high")
        assert len(high) == 1
        assert high[0]["severity"] == "high"

    def test_get_findings_filter_medium(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        medium = svc.get_findings(TENANT, severity="medium")
        assert len(medium) == 1

    def test_get_findings_sorted_by_severity_desc(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        findings = svc.get_findings(TENANT)
        severities = [f["severity"] for f in findings]
        assert severities == ["critical", "high", "medium"]

    def test_get_findings_limit(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        findings = svc.get_findings(TENANT, limit=1)
        assert len(findings) == 1

    def test_get_findings_empty_tenant(self):
        svc = CSPMService()
        findings = svc.get_findings("no-such-tenant")
        assert findings == []

    def test_get_findings_wrong_status(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        remediated = svc.get_findings(TENANT, status="remediated")
        assert len(remediated) == 0

    def test_findings_have_rule_id(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1", benchmark="cis")
        findings = svc.get_findings(TENANT)
        for f in findings:
            assert f["rule_id"].startswith("cis-")

    def test_findings_contain_remediation_text(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        findings = svc.get_findings(TENANT)
        for f in findings:
            assert f["remediation"] != ""


class TestCSPMRemediation:
    """Creating remediations for CSPM findings."""

    def test_create_remediation_manual(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        findings = svc.get_findings(TENANT, severity="high")
        fid = findings[0]["id"]
        result = svc.create_remediation(fid, auto_fix=False)
        assert result["status"] == "pending"
        assert result["finding_id"] == fid
        assert result["auto_fix"] is False

    def test_create_remediation_auto_fix(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        findings = svc.get_findings(TENANT, severity="high")
        fid = findings[0]["id"]
        result = svc.create_remediation(fid, auto_fix=True)
        assert result["status"] == "applied"
        assert result["auto_fix"] is True
        assert result["applied_at"] is not None

    def test_auto_fix_marks_finding_remediated(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        findings = svc.get_findings(TENANT, severity="high")
        fid = findings[0]["id"]
        svc.create_remediation(fid, auto_fix=True)
        # Finding should now be remediated and not appear in open findings
        open_high = svc.get_findings(TENANT, severity="high")
        assert len(open_high) == 0

    def test_auto_fix_critical_not_allowed(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        findings = svc.get_findings(TENANT, severity="critical")
        fid = findings[0]["id"]
        result = svc.create_remediation(fid, auto_fix=True)
        assert "error" in result
        assert "not auto-fixable" in result["error"]

    def test_remediation_not_found(self):
        svc = CSPMService()
        result = svc.create_remediation("fake-id")
        assert "error" in result
        assert "Finding not found" in result["error"]

    def test_remediation_has_steps(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        findings = svc.get_findings(TENANT, severity="medium")
        fid = findings[0]["id"]
        result = svc.create_remediation(fid, auto_fix=False)
        assert len(result["steps"]) > 0


class TestCSPMPostureScore:
    """Cloud security posture score computation."""

    def test_posture_score_no_findings(self):
        svc = CSPMService()
        result = svc.get_posture_score(TENANT)
        assert result["score"] == 100.0
        assert result["total_findings"] == 0

    def test_posture_score_with_findings(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        result = svc.get_posture_score(TENANT)
        # 1 critical (15) + 1 high (7) + 1 medium (3) = 25 penalty
        assert result["score"] == 75.0
        assert result["total_findings"] == 3
        assert result["open_findings"] == 3

    def test_posture_score_improves_after_remediation(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        findings = svc.get_findings(TENANT, severity="high")
        svc.create_remediation(findings[0]["id"], auto_fix=True)
        result = svc.get_posture_score(TENANT)
        # After remediating high (7 penalty removed): 100 - 15 - 3 = 82
        assert result["score"] == 82.0
        assert result["remediated"] == 1

    def test_posture_score_never_below_zero(self):
        svc = CSPMService()
        # Run many scans to accumulate lots of findings
        for i in range(10):
            svc.run_scan(TENANT, f"conn-{i}")
        result = svc.get_posture_score(TENANT)
        assert result["score"] >= 0.0


class TestCSPMStats:
    """CSPM statistics reporting."""

    def test_stats_empty(self):
        svc = CSPMService()
        stats = svc.get_stats(TENANT)
        assert stats["total_findings"] == 0
        assert stats["total_scans"] == 0
        assert stats["total_remediations"] == 0

    def test_stats_after_scan(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        stats = svc.get_stats(TENANT)
        assert stats["total_findings"] == 3
        assert stats["total_scans"] == 1
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["medium"] == 1
        assert stats["by_status"]["open"] == 3

    def test_stats_auto_remediations(self):
        svc = CSPMService()
        svc.run_scan(TENANT, "conn-1")
        findings = svc.get_findings(TENANT, severity="high")
        svc.create_remediation(findings[0]["id"], auto_fix=True)
        stats = svc.get_stats(TENANT)
        assert stats["total_remediations"] == 1
        assert stats["auto_remediations_applied"] == 1


# ---------------------------------------------------------------------------
# SaaSShieldService
# ---------------------------------------------------------------------------


class TestSaaSShieldRegister:
    """Registering SaaS applications."""

    def test_register_app_basic(self):
        svc = SaaSShieldService()
        result = svc.register_app(TENANT, "Slack")
        assert result["app_name"] == "Slack"
        assert result["tenant_id"] == TENANT
        assert result["sanctioned"] is True
        assert result["risk_score"] == 0.0

    def test_register_with_type_and_auth(self):
        svc = SaaSShieldService()
        result = svc.register_app(TENANT, "Salesforce", app_type="crm", auth_method="saml")
        assert result["app_type"] == "crm"
        assert result["auth_method"] == "saml"

    @pytest.mark.parametrize("app_type", ["collaboration", "storage", "crm", "devops", "hr", "finance", "custom"])
    def test_register_all_app_types(self, app_type):
        svc = SaaSShieldService()
        result = svc.register_app(TENANT, f"app-{app_type}", app_type=app_type)
        assert result["app_type"] == app_type

    @pytest.mark.parametrize("auth_method", ["oauth", "saml", "api_key", "oidc", "basic"])
    def test_register_all_auth_methods(self, auth_method):
        svc = SaaSShieldService()
        result = svc.register_app(TENANT, f"app-{auth_method}", auth_method=auth_method)
        assert result["auth_method"] == auth_method

    def test_register_unsupported_type_falls_back_to_custom(self):
        svc = SaaSShieldService()
        result = svc.register_app(TENANT, "weird-app", app_type="blockchain")
        assert result["app_type"] == "custom"

    def test_register_unsupported_auth_falls_back_to_oauth(self):
        svc = SaaSShieldService()
        result = svc.register_app(TENANT, "weird-auth", auth_method="kerberos")
        assert result["auth_method"] == "oauth"

    def test_register_with_config(self):
        svc = SaaSShieldService()
        result = svc.register_app(TENANT, "Jira", config={"url": "https://jira.example.com"})
        assert result["config"]["url"] == "https://jira.example.com"


class TestSaaSShieldListApps:
    """Listing SaaS applications per tenant."""

    def test_list_empty(self):
        svc = SaaSShieldService()
        assert svc.list_apps(TENANT) == []

    def test_list_after_registering(self):
        svc = SaaSShieldService()
        svc.register_app(TENANT, "Slack")
        svc.register_app(TENANT, "Teams")
        apps = svc.list_apps(TENANT)
        assert len(apps) == 2

    def test_list_tenant_isolation(self):
        svc = SaaSShieldService()
        svc.register_app("tenant-a", "Slack")
        svc.register_app("tenant-b", "Teams")
        assert len(svc.list_apps("tenant-a")) == 1
        assert svc.list_apps("tenant-a")[0]["app_name"] == "Slack"


class TestSaaSShieldSessionMonitor:
    """Monitoring user sessions on SaaS apps."""

    def test_monitor_normal_session(self):
        svc = SaaSShieldService()
        app = svc.register_app(TENANT, "Slack")
        result = svc.monitor_session(app["id"], "user-1", "login")
        assert result["anomaly_detected"] is False
        assert result["risk_level"] == "low"
        assert result["user_id"] == "user-1"
        assert result["action"] == "login"

    def test_monitor_app_not_found(self):
        svc = SaaSShieldService()
        result = svc.monitor_session("fake-app", "user-1", "login")
        assert "error" in result

    def test_monitor_increments_session_count(self):
        svc = SaaSShieldService()
        app = svc.register_app(TENANT, "Slack")
        svc.monitor_session(app["id"], "user-1", "login")
        svc.monitor_session(app["id"], "user-1", "logout")
        apps = svc.list_apps(TENANT)
        assert apps[0]["total_sessions"] == 2

    def test_anomaly_admin_off_hours(self):
        svc = SaaSShieldService()
        app = svc.register_app(TENANT, "AdminPanel")
        result = svc.monitor_session(
            app["id"], "user-1", "admin_action", context={"off_hours": True}
        )
        assert result["anomaly_detected"] is True
        assert result["risk_level"] == "high"

    def test_anomaly_large_download(self):
        svc = SaaSShieldService()
        app = svc.register_app(TENANT, "Drive")
        result = svc.monitor_session(
            app["id"], "user-1", "data_download", context={"size_mb": 600}
        )
        assert result["anomaly_detected"] is True

    def test_anomaly_new_geolocation(self):
        svc = SaaSShieldService()
        app = svc.register_app(TENANT, "Email")
        result = svc.monitor_session(
            app["id"], "user-1", "login", context={"new_geolocation": True}
        )
        assert result["anomaly_detected"] is True

    def test_anomaly_high_api_calls(self):
        svc = SaaSShieldService()
        app = svc.register_app(TENANT, "API-App")
        result = svc.monitor_session(
            app["id"], "user-1", "api_call", context={"calls_per_minute": 200}
        )
        assert result["anomaly_detected"] is True

    def test_no_anomaly_normal_download(self):
        svc = SaaSShieldService()
        app = svc.register_app(TENANT, "Drive")
        result = svc.monitor_session(
            app["id"], "user-1", "data_download", context={"size_mb": 50}
        )
        assert result["anomaly_detected"] is False

    def test_no_anomaly_normal_api_call(self):
        svc = SaaSShieldService()
        app = svc.register_app(TENANT, "API-App")
        result = svc.monitor_session(
            app["id"], "user-1", "api_call", context={"calls_per_minute": 10}
        )
        assert result["anomaly_detected"] is False

    def test_risk_score_updates_with_anomalies(self):
        svc = SaaSShieldService()
        app = svc.register_app(TENANT, "Risky")
        # All anomalous sessions
        svc.monitor_session(app["id"], "u1", "admin_action", context={"off_hours": True})
        svc.monitor_session(app["id"], "u2", "admin_action", context={"off_hours": True})
        apps = svc.list_apps(TENANT)
        assert apps[0]["risk_score"] == 100.0
        assert apps[0]["anomalous_sessions"] == 2

    def test_risk_score_partial_anomalies(self):
        svc = SaaSShieldService()
        app = svc.register_app(TENANT, "Mixed")
        svc.monitor_session(app["id"], "u1", "login")  # normal
        svc.monitor_session(app["id"], "u2", "admin_action", context={"off_hours": True})  # anomaly
        apps = svc.list_apps(TENANT)
        assert apps[0]["risk_score"] == 50.0


class TestSaaSShieldShadowIT:
    """Shadow IT discovery and tracking."""

    def test_detect_shadow_it_basic(self):
        svc = SaaSShieldService()
        result = svc.detect_shadow_it(TENANT, {"app_name": "Dropbox", "source": "dns"})
        assert result["app_name"] == "Dropbox"
        assert result["discovered_source"] == "dns"
        assert result["status"] == "discovered"

    def test_detect_shadow_it_default_source(self):
        svc = SaaSShieldService()
        result = svc.detect_shadow_it(TENANT, {"app_name": "WeTransfer"})
        assert result["discovered_source"] == "network"

    def test_detect_shadow_it_with_user_count(self):
        svc = SaaSShieldService()
        result = svc.detect_shadow_it(TENANT, {"app_name": "Discord", "users_count": 15})
        assert result["users_count"] == 15

    def test_detect_shadow_it_risk_level(self):
        svc = SaaSShieldService()
        result = svc.detect_shadow_it(TENANT, {"app_name": "TorBrowser", "risk_level": "critical"})
        assert result["risk_level"] == "critical"

    def test_multiple_shadow_it_discoveries(self):
        svc = SaaSShieldService()
        svc.detect_shadow_it(TENANT, {"app_name": "App1"})
        svc.detect_shadow_it(TENANT, {"app_name": "App2"})
        assert len(svc._shadow_it[TENANT]) == 2


class TestSaaSShieldRiskSummary:
    """Risk summary across SaaS applications."""

    def test_risk_summary_empty(self):
        svc = SaaSShieldService()
        result = svc.get_risk_summary(TENANT)
        assert result["total_apps"] == 0
        assert result["avg_risk_score"] == 0.0

    def test_risk_summary_with_apps(self):
        svc = SaaSShieldService()
        svc.register_app(TENANT, "Slack")
        svc.register_app(TENANT, "Teams")
        result = svc.get_risk_summary(TENANT)
        assert result["total_apps"] == 2
        assert result["sanctioned_apps"] == 2

    def test_risk_summary_shadow_it_count(self):
        svc = SaaSShieldService()
        svc.detect_shadow_it(TENANT, {"app_name": "ShadowApp"})
        result = svc.get_risk_summary(TENANT)
        assert result["shadow_it_count"] == 1

    def test_risk_summary_high_risk_apps(self):
        svc = SaaSShieldService()
        app = svc.register_app(TENANT, "Risky")
        # Generate all-anomalous sessions to get risk_score > 50
        svc.monitor_session(app["id"], "u1", "admin_action", context={"off_hours": True})
        result = svc.get_risk_summary(TENANT)
        assert result["high_risk_apps"] == 1

    def test_risk_summary_session_counts(self):
        svc = SaaSShieldService()
        app = svc.register_app(TENANT, "App")
        svc.monitor_session(app["id"], "u1", "login")
        svc.monitor_session(app["id"], "u1", "data_download", context={"size_mb": 600})
        result = svc.get_risk_summary(TENANT)
        assert result["total_sessions"] == 2
        assert result["anomalous_sessions"] == 1


class TestSaaSShieldStats:
    """SaaS Shield statistics."""

    def test_stats_empty(self):
        svc = SaaSShieldService()
        stats = svc.get_stats(TENANT)
        assert stats["total_apps"] == 0
        assert stats["total_sessions"] == 0

    def test_stats_by_type(self):
        svc = SaaSShieldService()
        svc.register_app(TENANT, "Slack", app_type="collaboration")
        svc.register_app(TENANT, "Drive", app_type="storage")
        stats = svc.get_stats(TENANT)
        assert stats["by_type"]["collaboration"] == 1
        assert stats["by_type"]["storage"] == 1

    def test_stats_by_auth_method(self):
        svc = SaaSShieldService()
        svc.register_app(TENANT, "App1", auth_method="oauth")
        svc.register_app(TENANT, "App2", auth_method="saml")
        stats = svc.get_stats(TENANT)
        assert stats["by_auth_method"]["oauth"] == 1
        assert stats["by_auth_method"]["saml"] == 1

    def test_stats_shadow_it(self):
        svc = SaaSShieldService()
        svc.detect_shadow_it(TENANT, {"app_name": "ShadowApp"})
        stats = svc.get_stats(TENANT)
        assert stats["shadow_it_discovered"] == 1


# ---------------------------------------------------------------------------
# HybridMeshService
# ---------------------------------------------------------------------------


class TestHybridMeshRegister:
    """Registering environments in the hybrid mesh."""

    def test_register_on_prem(self):
        svc = HybridMeshService()
        result = svc.register_environment(TENANT, "dc-west", "on_prem", endpoint="10.0.0.1")
        assert result["env_name"] == "dc-west"
        assert result["env_type"] == "on_prem"
        assert result["endpoint"] == "10.0.0.1"
        assert result["status"] == "active"

    def test_register_cloud(self):
        svc = HybridMeshService()
        result = svc.register_environment(TENANT, "aws-prod", "cloud")
        assert result["env_type"] == "cloud"

    def test_register_edge(self):
        svc = HybridMeshService()
        result = svc.register_environment(TENANT, "edge-01", "edge")
        assert result["env_type"] == "edge"

    @pytest.mark.parametrize("env_type", ["on_prem", "cloud", "edge", "colocation", "branch"])
    def test_register_all_env_types(self, env_type):
        svc = HybridMeshService()
        result = svc.register_environment(TENANT, f"env-{env_type}", env_type)
        assert result["env_type"] == env_type

    def test_register_unsupported_type_defaults_to_cloud(self):
        svc = HybridMeshService()
        result = svc.register_environment(TENANT, "mystery", "satellite")
        assert result["env_type"] == "cloud"

    def test_register_with_config(self):
        svc = HybridMeshService()
        result = svc.register_environment(
            TENANT, "dc-east", "on_prem", config={"rack": "A3"}
        )
        assert result["config"]["rack"] == "A3"

    def test_register_unique_ids(self):
        svc = HybridMeshService()
        r1 = svc.register_environment(TENANT, "env-1", "cloud")
        r2 = svc.register_environment(TENANT, "env-2", "cloud")
        assert r1["id"] != r2["id"]

    def test_register_initial_state(self):
        svc = HybridMeshService()
        result = svc.register_environment(TENANT, "new-env", "cloud")
        assert result["node_count"] == 0
        assert result["policies_synced"] == 0
        assert result["federated_with"] == []


class TestHybridMeshList:
    """Listing environments per tenant."""

    def test_list_empty(self):
        svc = HybridMeshService()
        assert svc.list_environments(TENANT) == []

    def test_list_after_registering(self):
        svc = HybridMeshService()
        svc.register_environment(TENANT, "env-a", "cloud")
        svc.register_environment(TENANT, "env-b", "on_prem")
        envs = svc.list_environments(TENANT)
        assert len(envs) == 2

    def test_list_tenant_isolation(self):
        svc = HybridMeshService()
        svc.register_environment("tenant-a", "env-a", "cloud")
        svc.register_environment("tenant-b", "env-b", "edge")
        assert len(svc.list_environments("tenant-a")) == 1
        assert len(svc.list_environments("tenant-b")) == 1


class TestHybridMeshRemove:
    """Removing environments from the mesh."""

    def test_remove_environment(self):
        svc = HybridMeshService()
        env = svc.register_environment(TENANT, "temp-env", "cloud")
        assert svc.remove_environment(TENANT, env["id"]) is True
        assert svc.list_environments(TENANT) == []

    def test_remove_nonexistent(self):
        svc = HybridMeshService()
        assert svc.remove_environment(TENANT, "fake-id") is False

    def test_remove_wrong_tenant(self):
        svc = HybridMeshService()
        env = svc.register_environment("tenant-a", "env-a", "cloud")
        assert svc.remove_environment("tenant-b", env["id"]) is False

    def test_remove_cleans_federation_links(self):
        svc = HybridMeshService()
        e1 = svc.register_environment(TENANT, "env-1", "cloud")
        e2 = svc.register_environment(TENANT, "env-2", "on_prem")
        svc.federate_nodes(TENANT, [e1["id"], e2["id"]])
        svc.remove_environment(TENANT, e1["id"])
        # e2 should no longer have e1 in federated_with
        remaining = svc.list_environments(TENANT)
        assert len(remaining) == 1
        assert e1["id"] not in remaining[0]["federated_with"]


class TestHybridMeshPolicySync:
    """Synchronising policies between environments."""

    def test_sync_policies_basic(self):
        svc = HybridMeshService()
        src = svc.register_environment(TENANT, "source", "cloud")
        tgt = svc.register_environment(TENANT, "target", "on_prem")
        result = svc.sync_policies(TENANT, src["id"], tgt["id"])
        assert result["status"] == "completed"
        assert result["policies_count"] >= 5
        assert result["completed_at"] is not None

    def test_sync_source_not_found(self):
        svc = HybridMeshService()
        tgt = svc.register_environment(TENANT, "target", "cloud")
        result = svc.sync_policies(TENANT, "fake-src", tgt["id"])
        assert "error" in result
        assert "Source" in result["error"]

    def test_sync_target_not_found(self):
        svc = HybridMeshService()
        src = svc.register_environment(TENANT, "source", "cloud")
        result = svc.sync_policies(TENANT, src["id"], "fake-tgt")
        assert "error" in result
        assert "Target" in result["error"]

    def test_sync_wrong_tenant_source(self):
        svc = HybridMeshService()
        src = svc.register_environment("other-tenant", "source", "cloud")
        tgt = svc.register_environment(TENANT, "target", "cloud")
        result = svc.sync_policies(TENANT, src["id"], tgt["id"])
        assert "error" in result

    def test_sync_wrong_tenant_target(self):
        svc = HybridMeshService()
        src = svc.register_environment(TENANT, "source", "cloud")
        tgt = svc.register_environment("other-tenant", "target", "cloud")
        result = svc.sync_policies(TENANT, src["id"], tgt["id"])
        assert "error" in result

    def test_sync_updates_target_policies_synced(self):
        svc = HybridMeshService()
        src = svc.register_environment(TENANT, "source", "cloud")
        tgt = svc.register_environment(TENANT, "target", "on_prem")
        result = svc.sync_policies(TENANT, src["id"], tgt["id"])
        envs = svc.list_environments(TENANT)
        target_env = [e for e in envs if e["env_name"] == "target"][0]
        assert target_env["policies_synced"] == result["policies_count"]
        assert target_env["last_sync_at"] is not None

    def test_sync_accumulates_policies(self):
        svc = HybridMeshService()
        src = svc.register_environment(TENANT, "source", "cloud")
        tgt = svc.register_environment(TENANT, "target", "on_prem")
        r1 = svc.sync_policies(TENANT, src["id"], tgt["id"])
        r2 = svc.sync_policies(TENANT, src["id"], tgt["id"])
        envs = svc.list_environments(TENANT)
        target_env = [e for e in envs if e["env_name"] == "target"][0]
        assert target_env["policies_synced"] == r1["policies_count"] + r2["policies_count"]


class TestHybridMeshFederation:
    """Federating nodes across environments."""

    def test_federate_two_environments(self):
        svc = HybridMeshService()
        e1 = svc.register_environment(TENANT, "env-1", "cloud")
        e2 = svc.register_environment(TENANT, "env-2", "on_prem")
        result = svc.federate_nodes(TENANT, [e1["id"], e2["id"]])
        assert result["federated_environments"] == 2
        assert result["new_links"] == 1

    def test_federate_three_environments(self):
        svc = HybridMeshService()
        e1 = svc.register_environment(TENANT, "env-1", "cloud")
        e2 = svc.register_environment(TENANT, "env-2", "on_prem")
        e3 = svc.register_environment(TENANT, "env-3", "edge")
        result = svc.federate_nodes(TENANT, [e1["id"], e2["id"], e3["id"]])
        assert result["federated_environments"] == 3
        assert result["new_links"] == 3  # 3 pairs: (1,2), (1,3), (2,3)

    def test_federate_less_than_two_fails(self):
        svc = HybridMeshService()
        e1 = svc.register_environment(TENANT, "env-1", "cloud")
        result = svc.federate_nodes(TENANT, [e1["id"]])
        assert "error" in result
        assert "At least two" in result["error"]

    def test_federate_empty_list_fails(self):
        svc = HybridMeshService()
        result = svc.federate_nodes(TENANT, [])
        assert "error" in result

    def test_federate_idempotent(self):
        svc = HybridMeshService()
        e1 = svc.register_environment(TENANT, "env-1", "cloud")
        e2 = svc.register_environment(TENANT, "env-2", "on_prem")
        svc.federate_nodes(TENANT, [e1["id"], e2["id"]])
        result = svc.federate_nodes(TENANT, [e1["id"], e2["id"]])
        assert result["new_links"] == 0

    def test_federate_wrong_tenant_ignored(self):
        svc = HybridMeshService()
        e1 = svc.register_environment(TENANT, "env-1", "cloud")
        e2 = svc.register_environment("other-tenant", "env-2", "cloud")
        result = svc.federate_nodes(TENANT, [e1["id"], e2["id"]])
        assert "error" in result  # Only 1 valid env, need >= 2

    def test_federate_nonexistent_ids(self):
        svc = HybridMeshService()
        result = svc.federate_nodes(TENANT, ["fake-1", "fake-2"])
        assert "error" in result


class TestHybridMeshStatus:
    """Mesh status queries."""

    def test_mesh_status_empty(self):
        svc = HybridMeshService()
        result = svc.get_mesh_status(TENANT)
        assert result["total_environments"] == 0
        assert result["total_nodes"] == 0
        assert result["federation_links"] == 0

    def test_mesh_status_with_envs(self):
        svc = HybridMeshService()
        svc.register_environment(TENANT, "cloud-1", "cloud")
        svc.register_environment(TENANT, "prem-1", "on_prem")
        result = svc.get_mesh_status(TENANT)
        assert result["total_environments"] == 2
        assert result["by_type"]["cloud"] == 1
        assert result["by_type"]["on_prem"] == 1
        assert result["by_status"]["active"] == 2

    def test_mesh_status_federation_links(self):
        svc = HybridMeshService()
        e1 = svc.register_environment(TENANT, "env-1", "cloud")
        e2 = svc.register_environment(TENANT, "env-2", "on_prem")
        svc.federate_nodes(TENANT, [e1["id"], e2["id"]])
        result = svc.get_mesh_status(TENANT)
        assert result["federation_links"] == 1

    def test_mesh_status_syncs(self):
        svc = HybridMeshService()
        src = svc.register_environment(TENANT, "source", "cloud")
        tgt = svc.register_environment(TENANT, "target", "on_prem")
        svc.sync_policies(TENANT, src["id"], tgt["id"])
        result = svc.get_mesh_status(TENANT)
        assert result["total_syncs"] == 1


class TestHybridMeshLatencyMap:
    """Latency map computation."""

    def test_latency_map_empty(self):
        svc = HybridMeshService()
        result = svc.get_latency_map(TENANT)
        assert result["environment_count"] == 0
        assert result["latency_map"] == {}

    def test_latency_map_single_env(self):
        svc = HybridMeshService()
        svc.register_environment(TENANT, "env-1", "cloud")
        result = svc.get_latency_map(TENANT)
        assert result["environment_count"] == 1
        assert result["latency_map"]["env-1"]["env-1"] == 0.0

    def test_latency_map_two_envs(self):
        svc = HybridMeshService()
        svc.register_environment(TENANT, "env-1", "cloud")
        svc.register_environment(TENANT, "env-2", "on_prem")
        result = svc.get_latency_map(TENANT)
        assert result["environment_count"] == 2
        lmap = result["latency_map"]
        assert lmap["env-1"]["env-1"] == 0.0
        assert lmap["env-2"]["env-2"] == 0.0
        assert lmap["env-1"]["env-2"] > 0.0
        assert lmap["env-2"]["env-1"] > 0.0

    def test_latency_map_self_latency_zero(self):
        svc = HybridMeshService()
        svc.register_environment(TENANT, "env-a", "edge")
        result = svc.get_latency_map(TENANT)
        assert result["latency_map"]["env-a"]["env-a"] == 0.0


class TestHybridMeshStats:
    """Hybrid mesh statistics."""

    def test_stats_empty(self):
        svc = HybridMeshService()
        stats = svc.get_stats(TENANT)
        assert stats["total_environments"] == 0
        assert stats["active_environments"] == 0
        assert stats["total_federation_links"] == 0
        assert stats["total_policy_syncs"] == 0

    def test_stats_after_registering(self):
        svc = HybridMeshService()
        svc.register_environment(TENANT, "env-1", "cloud")
        svc.register_environment(TENANT, "env-2", "on_prem")
        stats = svc.get_stats(TENANT)
        assert stats["total_environments"] == 2
        assert stats["active_environments"] == 2

    def test_stats_federation_links(self):
        svc = HybridMeshService()
        e1 = svc.register_environment(TENANT, "env-1", "cloud")
        e2 = svc.register_environment(TENANT, "env-2", "on_prem")
        svc.federate_nodes(TENANT, [e1["id"], e2["id"]])
        stats = svc.get_stats(TENANT)
        assert stats["total_federation_links"] == 1

    def test_stats_syncs(self):
        svc = HybridMeshService()
        src = svc.register_environment(TENANT, "source", "cloud")
        tgt = svc.register_environment(TENANT, "target", "on_prem")
        svc.sync_policies(TENANT, src["id"], tgt["id"])
        stats = svc.get_stats(TENANT)
        assert stats["total_policy_syncs"] == 1
        assert stats["successful_syncs"] == 1
        assert stats["failed_syncs"] == 0

    def test_stats_policies_synced_total(self):
        svc = HybridMeshService()
        src = svc.register_environment(TENANT, "source", "cloud")
        tgt = svc.register_environment(TENANT, "target", "on_prem")
        svc.sync_policies(TENANT, src["id"], tgt["id"])
        stats = svc.get_stats(TENANT)
        assert stats["total_policies_synced"] > 0
