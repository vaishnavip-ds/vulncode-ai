# VulnCode AI architecture

## GitHub-native flow

1. GitHub sends a signed `push` webhook; the API validates the HMAC and deduplicates the delivery.
2. GitHub Actions runs Semgrep against the exact commit and uploads its JSON result.
3. VulnCode AI stores normalized findings and publishes a GitHub Check with inline annotations.
4. Supported checks include a native **Create safe fixes** requested action.
5. GitHub sends a signed `check_run.requested_action` webhook when a developer clicks it.
6. A background remediation job retrieves the exact source file through the installation token.
7. The generator produces only a supported narrow patch; the validator checks syntax, change size, and new dangerous primitives.
8. The delivery adapter rechecks source content, creates a remediation branch, and opens a draft PR.
9. The developer reviews and merges—or rejects—the change entirely inside GitHub.

```text
push / pull request
        │
        ▼
GitHub Action + Semgrep ──> FastAPI ──> PostgreSQL
                                  │
                                  ▼
                       GitHub Check annotations
                                  │
                        Create safe fixes button
                                  │
                                  ▼
                     validator ──> draft GitHub PR
```

## Service boundaries

- `services/semgrep.py`: scanner normalization.
- `PatchGenerator`: replaceable remediation engine contract.
- `DeterministicValidator`: auditable safety checks.
- `services/remediation.py`: orchestration invoked by GitHub Check actions.
- `GitHubAppClient`: installation authentication, Checks, Contents, branches, and PR delivery.
- FastAPI webhook routes: signed GitHub event boundary.

## Scale path

Keep API replicas stateless and move requested-action work to a durable queue. Run model inference and repository validation in separate sandboxed workers without GitHub credentials. Store artifacts in object storage and metadata in PostgreSQL. Pin scanner, generator, model, prompt, and policy versions. Add per-installation authorization, append-only audit events, structured telemetry, and tenant isolation before wider rollout.

