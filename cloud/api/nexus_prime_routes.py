"""AngelClaw V8.1 — Nexus Prime: Quantum Crypto, Attack Surface, Runtime Protection API routes."""

from __future__ import annotations

from fastapi import APIRouter, Header

router = APIRouter(prefix="/api/v1/nexus-prime", tags=["Nexus Prime"])


# -- Quantum Crypto --

@router.post("/crypto/scan")
def nexus_scan_crypto(targets: list[str] = [], tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.quantum_crypto import quantum_crypto_service
    return quantum_crypto_service.scan_crypto_inventory(tenant_id, targets or None)


@router.get("/crypto/agility")
def nexus_assess_agility(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.quantum_crypto import quantum_crypto_service
    return quantum_crypto_service.assess_agility(tenant_id)


@router.post("/crypto/migration-plan")
def nexus_create_migration(plan_data: dict = {}, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.quantum_crypto import quantum_crypto_service
    return quantum_crypto_service.create_migration_plan(tenant_id, plan_data)


@router.get("/crypto/migration-plans")
def nexus_get_migrations(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.quantum_crypto import quantum_crypto_service
    return quantum_crypto_service.get_migration_plans(tenant_id)


@router.post("/crypto/generate-keypair")
def nexus_generate_keypair(algorithm: str = "kyber-1024", tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.quantum_crypto import quantum_crypto_service
    return quantum_crypto_service.generate_pqc_keypair(tenant_id, algorithm)


@router.get("/crypto/status")
def nexus_crypto_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.quantum_crypto import quantum_crypto_service
    return quantum_crypto_service.status(tenant_id)


# -- Attack Surface Management --

@router.post("/asm/discover")
def nexus_discover_assets(domains: list[str], tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.attack_surface import attack_surface_service
    return attack_surface_service.discover_assets(tenant_id, domains)


@router.get("/asm/exposure-map")
def nexus_exposure_map(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.attack_surface import attack_surface_service
    return attack_surface_service.get_exposure_map(tenant_id)


@router.get("/asm/changes")
def nexus_surface_changes(since_hours: int = 24, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.attack_surface import attack_surface_service
    return attack_surface_service.monitor_changes(tenant_id, since_hours)


@router.get("/asm/certificates")
def nexus_scan_certs(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.attack_surface import attack_surface_service
    return attack_surface_service.scan_certificates(tenant_id)


@router.post("/asm/discover-apis")
def nexus_discover_apis(base_url: str, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.attack_surface import attack_surface_service
    return attack_surface_service.discover_apis(tenant_id, base_url)


@router.get("/asm/status")
def nexus_asm_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.attack_surface import attack_surface_service
    return attack_surface_service.status(tenant_id)


# -- Runtime Application Self-Protection --

@router.post("/rasp/analyze")
def nexus_analyze_request(request_data: dict = {}, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.runtime_protection import runtime_protection_service
    return runtime_protection_service.analyze_request(tenant_id, request_data)


@router.get("/rasp/blocked")
def nexus_blocked_requests(limit: int = 20, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.runtime_protection import runtime_protection_service
    return runtime_protection_service.get_blocked_requests(tenant_id, limit)


@router.post("/rasp/rule")
def nexus_add_rasp_rule(rule: dict = {}, tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.runtime_protection import runtime_protection_service
    return runtime_protection_service.add_rule(tenant_id, rule)


@router.get("/rasp/stats")
def nexus_rasp_stats(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.runtime_protection import runtime_protection_service
    return runtime_protection_service.get_stats(tenant_id)


@router.get("/rasp/status")
def nexus_rasp_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.runtime_protection import runtime_protection_service
    return runtime_protection_service.status(tenant_id)


# -- Combined Status --

@router.get("/status")
def nexus_prime_status(tenant_id: str = Header("dev-tenant", alias="X-TENANT-ID")):
    from cloud.services.quantum_crypto import quantum_crypto_service
    from cloud.services.attack_surface import attack_surface_service
    from cloud.services.runtime_protection import runtime_protection_service
    return {
        "version": "8.1.0",
        "codename": "Nexus Prime",
        "quantum_crypto": quantum_crypto_service.status(tenant_id),
        "attack_surface": attack_surface_service.status(tenant_id),
        "runtime_protection": runtime_protection_service.status(tenant_id),
    }
