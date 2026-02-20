"""Tests for V8.1.0 Nexus Prime: Quantum Crypto, Attack Surface Management, Runtime Protection."""

from __future__ import annotations

from cloud.services.attack_surface import AttackSurfaceService
from cloud.services.quantum_crypto import QuantumCryptoService
from cloud.services.runtime_protection import RuntimeProtectionService

TENANT = "test-tenant"


# ===========================================================================
# QuantumCryptoService
# ===========================================================================


class TestQuantumCryptoService:
    """QuantumCryptoService tests."""

    def test_scan_crypto_inventory(self):
        svc = QuantumCryptoService()
        result = svc.scan_crypto_inventory(TENANT, ["server-1", "server-2"])
        assert result["tenant_id"] == TENANT
        assert result["assets_scanned"] == 2
        assert "readiness_score" in result
        assert "quantum_vulnerable" in result

    def test_scan_without_targets(self):
        svc = QuantumCryptoService()
        result = svc.scan_crypto_inventory(TENANT)
        assert result["assets_scanned"] == 5

    def test_assess_agility(self):
        svc = QuantumCryptoService()
        result = svc.assess_agility(TENANT)
        assert result["tenant_id"] == TENANT
        assert "agility_score" in result
        assert result["hybrid_mode_ready"] is True

    def test_create_migration_plan(self):
        svc = QuantumCryptoService()
        result = svc.create_migration_plan(
            TENANT, {"name": "RSA-to-Kyber", "target_algorithm": "kyber-1024"}
        )
        assert "id" in result
        assert result["tenant_id"] == TENANT
        assert result["target_algorithm"] == "kyber-1024"

    def test_get_migration_plans(self):
        svc = QuantumCryptoService()
        svc.create_migration_plan(TENANT, {"name": "plan-1", "target_algorithm": "kyber-512"})
        plans = svc.get_migration_plans(TENANT)
        assert len(plans) >= 1

    def test_generate_pqc_keypair(self):
        svc = QuantumCryptoService()
        result = svc.generate_pqc_keypair(TENANT, "kyber-1024")
        assert result["algorithm"] == "kyber-1024"
        assert result["quantum_safe"] is True
        assert result["key_size"] == 1568

    def test_generate_keypair_unique(self):
        svc = QuantumCryptoService()
        k1 = svc.generate_pqc_keypair(TENANT)
        k2 = svc.generate_pqc_keypair(TENANT)
        assert k1["id"] != k2["id"]

    def test_status(self):
        svc = QuantumCryptoService()
        result = svc.status(TENANT)
        assert result["service"] == "QuantumCryptoService"
        assert result["version"] == "8.1.0"


# ===========================================================================
# AttackSurfaceService
# ===========================================================================


class TestAttackSurfaceService:
    """AttackSurfaceService tests."""

    def test_discover_assets(self):
        svc = AttackSurfaceService()
        result = svc.discover_assets(TENANT, ["example.com", "api.example.com"])
        assert result["domains_scanned"] == 2
        assert result["assets_found"] == 2
        assert len(result["assets"]) == 2

    def test_discover_single_domain(self):
        svc = AttackSurfaceService()
        result = svc.discover_assets(TENANT, ["test.com"])
        assert result["assets_found"] == 1

    def test_get_exposure_map(self):
        svc = AttackSurfaceService()
        svc.discover_assets(TENANT, ["exposed.com"])
        result = svc.get_exposure_map(TENANT)
        assert result["total_assets"] >= 1
        assert "avg_exposure_score" in result

    def test_exposure_map_empty(self):
        svc = AttackSurfaceService()
        result = svc.get_exposure_map("empty-tenant")
        assert result["total_assets"] == 0

    def test_monitor_changes(self):
        svc = AttackSurfaceService()
        result = svc.monitor_changes(TENANT)
        assert isinstance(result, list)

    def test_scan_certificates(self):
        svc = AttackSurfaceService()
        svc.discover_assets(TENANT, ["secure.com"])
        certs = svc.scan_certificates(TENANT)
        assert len(certs) >= 1
        assert certs[0]["valid"] is True

    def test_discover_apis(self):
        svc = AttackSurfaceService()
        result = svc.discover_apis(TENANT, "https://api.example.com")
        assert result["endpoints_found"] == 12
        assert result["base_url"] == "https://api.example.com"

    def test_status(self):
        svc = AttackSurfaceService()
        result = svc.status(TENANT)
        assert result["service"] == "AttackSurfaceService"
        assert result["version"] == "8.1.0"


# ===========================================================================
# RuntimeProtectionService
# ===========================================================================


class TestRuntimeProtectionService:
    """RuntimeProtectionService tests."""

    def test_analyze_clean_request(self):
        svc = RuntimeProtectionService()
        result = svc.analyze_request(TENANT, {"body": "Hello world", "path": "/api/data"})
        assert result["blocked"] is False
        assert result["action"] == "allow"

    def test_analyze_sqli_attack(self):
        svc = RuntimeProtectionService()
        result = svc.analyze_request(TENANT, {"body": "SELECT * FROM users WHERE id=1 OR 1=1--"})
        assert result["blocked"] is True
        assert "sqli" in result["attacks_detected"]
        assert result["severity"] == "critical"

    def test_analyze_xss_attack(self):
        svc = RuntimeProtectionService()
        result = svc.analyze_request(TENANT, {"body": '<script>alert("xss")</script>'})
        assert result["blocked"] is True
        assert "xss" in result["attacks_detected"]

    def test_analyze_path_traversal(self):
        svc = RuntimeProtectionService()
        result = svc.analyze_request(TENANT, {"body": "../../etc/passwd"})
        assert result["blocked"] is True
        assert "path_traversal" in result["attacks_detected"]

    def test_get_blocked_requests(self):
        svc = RuntimeProtectionService()
        svc.analyze_request(TENANT, {"body": "DROP TABLE users"})
        blocked = svc.get_blocked_requests(TENANT)
        assert len(blocked) >= 1

    def test_add_rule(self):
        svc = RuntimeProtectionService()
        result = svc.add_rule(TENANT, {"pattern": "eval\\(", "action": "block"})
        assert "id" in result
        assert result["status"] == "active"

    def test_get_stats(self):
        svc = RuntimeProtectionService()
        svc.analyze_request(TENANT, {"body": "UNION SELECT password FROM users"})
        stats = svc.get_stats(TENANT)
        assert stats["blocked_attacks"] >= 1

    def test_status(self):
        svc = RuntimeProtectionService()
        result = svc.status(TENANT)
        assert result["service"] == "RuntimeProtectionService"
        assert result["version"] == "8.1.0"
