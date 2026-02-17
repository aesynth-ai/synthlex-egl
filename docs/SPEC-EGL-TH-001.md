# SPEC-EGL-TH-001

Placeholder spec for Synthlex EGL.

## Run

- node runner.mjs --pack tests/packs/TH-001B.pack.json --run-id A
- node runner.mjs --pack tests/packs/TH-001B.pack.json --run-id LIVE1 --attest live
- node tests/packs/golden.mjs --pack tests/packs/TH-001B.pack.json --runA BA --runB BB

## TH-001C (proxy boundary)

- node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id PC --attest mock --source proxy
- node runner.mjs --pack tests/packs/TH-001C.pack.json --run-id PD --attest mock --source proxy
- node tests/packs/TH-001C.golden.mjs --pack tests/packs/TH-001C.pack.json --runA PC --runB PD

## Proxy (dry-run)

- node harness/tdi/proxy/proxy.mjs --pack tests/packs/TH-001C.proxy.pack.json --run-id A
