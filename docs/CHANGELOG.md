# AngelClaw AGI Guardian — Changelog

## V3.0.0 — Dominion (2026-02-19)
### Admin Console & Organization Visibility
- Full org-wide dashboard: Halo Score, Wingspan, fleet status, alert counts
- Tenant management with per-tenant metrics and agent counts
- Per-agent detail views with event history, alerts, anti-tamper status
- Angel Legion warden status panel with performance metrics

### Anti-Tamper Protection
- Three modes: OFF, MONITOR, ENFORCE
- Per-agent and per-tenant configuration
- Heartbeat monitoring, binary checksum verification
- Tamper event logging with severity and resolution tracking

### Self-Learning Feedback Loop
- Operator accept/reject/ignore/modify tracking on suggestions
- Per-tenant acceptance rate and suggestion ranking
- Automatic adjustment recommendations (verbosity, thresholds, autonomy)

### Self-Hardening Engine
- Autonomous security weakness detection and correction
- Six check types: scan failures, loose allowlists, missing logs, weak auth, unprotected agents, repeated misconfigs
- Observe/suggest/auto_apply autonomy modes
- Every action logged with full explanation and revertible

### Multi-Platform Support
- Responsive admin console UI (sidebar navigation, 10 pages)
- PWA manifest and service worker for mobile install
- iOS/Android/DuckDuckGo mobile access instructions
- Chrome/Chromium browser extension (v3.0.0) with badge alerts, mini chat, quick actions

### Brain Upgrade
- Admin console intents: org overview, fleet deep dive, anti-tamper, feedback, hardening
- Feedback loop integration in daemon cycle
- Self-hardening cycle in daemon loop
- Anti-tamper heartbeat monitoring in daemon

### Security & Infrastructure
- 50+ REST API endpoints across 20 route modules
- Rate limiting, CORS, security headers middleware
- API key authentication alongside JWT
- Custom RBAC roles
- Full audit trail for all hardening and feedback actions

### Testing
- 1758+ tests passing (88%+ coverage)
- New test suites: test_v30_admin_console.py, test_v30_services.py

## V2.5.0 — Ascension (2025)
- Plugin architecture with dynamic loading
- API key management (create, revoke, rotate)
- Backup and restore functionality
- CSV/JSON data export
- Enhanced brain with plugin and API key intents

## V2.4.0 — Fortress (2025)
- Policy CRUD API with validation
- Agent quarantine (isolation and timed release)
- Notification channels (Slack, Discord, webhook)
- WebSocket real-time feeds
- Compliance warden (GDPR, HIPAA, PCI)
- API security warden (abuse cascade detection)

## V2.2.0 — Enhanced Seraph (2025)
- Angel Legion orchestrator sweep in daemon
- Learning engine maintenance cycle (FP decay, threshold tuning)
- Detection effectiveness scoring
- Pattern correlation tracking
- Escalation rate monitoring
- Prediction calibration

## V2.1.0 — Seraph Brain (2025)
- Enhanced brain with GOD MODE cognition
- 35 new detection patterns
- 45+ NLP intents (English + Hebrew)
- Deep diagnostic mode

## V2.0.0 — Angel Legion (2025)
- 7 specialized wardens (network, secrets, toolchain, behavior, timeline, browser, core)
- Dynamic agent registry (scale to N agents)
- Circuit breaker for failing wardens
- Autonomy modes: observe, suggest, auto_apply
- Incident lifecycle management

## V1.2.0 — Autonomous Guardian (2025)
- Autonomous daemon (24/7 background scanning)
- Shield assessment (ClawSec threat detection)
- Drift detection and agent health monitoring
- Activity logging with human-friendly summaries

## V1.0.0 — Initial Release (2025)
- ANGELNODE edge agent with PolicyEngine (29 built-in rules)
- Cloud API with event ingestion and policy distribution
- Zero-trust bootstrap policy (540 rules, default-deny)
- AI Assistant (incident summary, policy proposals)
- Guardian scan and reporting
- Web dashboard (single-page, dark theme)
