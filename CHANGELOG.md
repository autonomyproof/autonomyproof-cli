# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.17.0]

### Added
- **AG036 — Persistence-sensitive file write exposed to the agent.** Flags an agent tool that
  writes to a file granting persistence or backdoor access (SSH `authorized_keys`, `crontab`,
  `/etc/sudoers`, shell rc files, systemd units) with no approval — turning a one-shot prompt
  injection into durable, privileged access. MITRE ATT&CK T1098 + T1547.
- **AG037 — Runtime package installation exposed to the agent.** Flags an agent tool that runs
  `pip`/`npm`/`uv`/`poetry` install via a shell executor — installing an arbitrary package
  executes arbitrary code (RCE / supply-chain). MITRE ATT&CK T1059 + T1195.

Both reuse the tool-scoped, approval-suppressed model (new `_iter_marker_action_tools` spine):
they fire only when a sensitive marker AND a real action co-occur inside an unguarded tool, so
reads, ordinary file writes, non-tool functions, and help text stay silent. Verified: corpus
precision/recall 1.000, 0 findings across the 41-repo real benchmark.

## [0.16.0]

### Added
- **AG034 — Cloud/infrastructure destruction exposed to the agent.** Flags an agent tool that
  can tear down cloud infrastructure with no approval: AWS `terminate_instances`,
  `delete_bucket`, `delete_db_instance`, `delete_cluster`, `delete_stack`, `delete_volume`,
  and Kubernetes `delete_namespaced_*` / `delete_collection_*` / `delete_namespace`. Mapped to
  MITRE ATT&CK T1485 + T1531.
- **AG035 — Money movement exposed to the agent without approval.** Flags `Refund.create`,
  `Payout.create`, and `Transfer.create` (Stripe-style) inside an agent tool with no approval
  gate — the classic prompt-injection payout attack.

Both reuse AG033's call-based, tool-scoped, approval-suppressed model (the shared
`_iter_tool_sinks` spine), so they stay zero-false-positive. Verified: corpus precision/recall
1.000, and 0 findings across the 41-repo real benchmark.

## [0.15.0]

### Added
- **AG033 — Irreversible data destruction exposed to the agent.** Flags an agent tool that
  can wipe an entire datastore or directory tree with no approval step: `drop_all`,
  `drop_database`, `drop_collection`, `flushall`/`flushdb`, `shutil.rmtree`, and embedded
  `DROP DATABASE` / `DROP TABLE` / `TRUNCATE TABLE`. Unlike the string-only AG019, this is
  **call-based** (it catches `db.drop_all()` and `redis.flushall()`, which carry no SQL
  literal) and is **scoped to registered agent tools without an approval gate**, so it stays
  zero-false-positive. The overloaded bare `.drop(` (e.g. pandas `df.drop(columns=...)`) is
  deliberately excluded. Mapped to MITRE ATT&CK T1485 (Data Destruction) and T1561 (Disk Wipe).

## [0.14.0]

### Changed
- AG021 broadened to cover `joblib.load`, `pandas.read_pickle`, and `numpy.load(allow_pickle=True)`.

## [0.13.0]

### Added
- AG026 version-validated CVE detection for known-vulnerable framework dependencies.
