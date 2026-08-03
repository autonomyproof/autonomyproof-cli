# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
