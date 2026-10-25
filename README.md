# CloudSentinel

> Cloud risk, explained.

CloudSentinel is a security research platform concept that turns cloud configuration data into **explainable attack paths**. Instead of presenting a flat list of misconfigurations, it connects identity trust, permissions, network reachability, and asset criticality to show which combinations create the most dangerous routes to sensitive resources.

This repository contains a polished, interactive MVP for a job-profile application. It includes the full product surface and a small deterministic reasoning engine that powers the demo analysis state.

## Product surface

- **Overview** — risk score, critical paths, assets at risk, analysis freshness, and activity.
- **Attack paths** — ranked reachability paths with evidence, assumptions, blast radius, and remediation guidance.
- **Findings** — confidence-aware findings connected to a path and an affected asset.
- **Validation** — before-and-after remediation history and control health.
- **Regression tests** — reusable checks derived from confirmed paths.
- **Assets & graph** — inventory of identities, resources, relationships, and connected sources.
- **Activity log** — tenant-scoped audit trail for analysis and change events.
- **Settings** — read-only source connections, AI reasoning preferences, SSO, and credential handling policy.

## Architecture

```text
src/
├── App.tsx              # App shell, screens, state, and user flows
├── security-engine.ts   # Typed graph model, path traversal, scoring, validation helpers
├── main.tsx             # React entry point
└── styles.css           # Responsive visual system and UI components
```

The demo engine is intentionally deterministic:

1. A cloud export is represented as nodes and typed relationship edges.
2. Entry points are traversed with bounded graph reachability.
3. Critical assets produce scored attack paths with explicit evidence.
4. A before/after graph can be compared to identify broken paths and regressions.
5. Confirmed paths can become reusable regression-test assertions.

The UI currently uses a safe local fixture so it can be run without cloud credentials. It does **not** connect to or modify an actual cloud account.

## Run locally

```bash
npm install
npm run dev
```

Open the local Vite URL shown in the terminal. The app is responsive and includes mobile navigation.

## Checks

```bash
npm run typecheck
npm run build
```

## Security posture for a production implementation

The next production layer would add:

- read-only AWS/GCP/Azure collectors or signed export ingestion;
- tenant-scoped storage for graph snapshots, findings, evidence, and audit events;
- policy-enforced authorization at the API and query layer;
- short-lived workload identity instead of long-lived cloud credentials;
- immutable analysis and remediation history;
- a sandbox runner for safe, bounded attack simulation test cases;
- background graph builds with idempotent job processing.

Any attack simulation should remain opt-in, allowlisted, bounded, and isolated to a controlled lab or explicitly authorized environment.

## Portfolio talking points

- “I designed the core product around relationships, not isolated severity labels.”
- “AI proposes hypotheses; deterministic graph rules verify reachability.”
- “Every high-risk result includes evidence, assumptions, confidence, and the smallest path-breaking change.”
- “Remediation is treated as a measurable hypothesis: validate the path disappeared and check for regressions.”
