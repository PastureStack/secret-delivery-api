# PastureStack Secret Delivery API

Secret Delivery API encrypts, signs, rewraps, and purges secret payloads for the preserved control-plane contract. It supports local AES-GCM keys and the inherited Vault transit integration.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

**Upstream:** [`rancher/secrets-api`](https://github.com/rancher/secrets-api). This GitHub fork preserves upstream history, authorship, dates, tags, licenses, and bundled dependency notices; PastureStack maintenance is consolidated into one commit after the preserved upstream boundary.

## Project status

The `v0.3.0` maintenance layer is based on the preserved upstream `v0.2.2` boundary. It uses Go modules and the exact Go 1.26.5 toolchain, deterministic Release packaging, bounded JSON requests, HTTP resource timeouts, scoped Vault storage operations, neutral product naming, race tests, a 70% critical-path coverage gate, and a loopback local-key API integration test. Production deployment remains disabled until the matching Server integration has passed in an isolated VM.

The `none` backend is an insecure compatibility fixture and is disabled by default. It can be enabled only with `--allow-insecure-none-backend` or `ALLOW_INSECURE_NONE_BACKEND=true` for an explicitly reviewed legacy migration. The supported Server path uses the `localkey` backend on the loopback interface.

## Build and test

From a Linux host with Go 1.26.5, `bash`, `tar`, `xz`, `curl`, and network access to the Go module proxy or an already populated module cache:

```sh
make test
make build
make integration-test
make package
make ci
```

For the reviewed compatibility release, set `VERSION_OVERRIDE=v0.3.0` and `SOURCE_DATE_EPOCH=0`. Packaging produces `secret-delivery-api-0.3.0-linux-amd64.tar.xz`. PastureStack Server downloads the flat asset from its matching GitHub Release, verifies its SHA-256 digest, and installs the executable under the preserved `secrets-api` compatibility name. Operators do not need to host an artifact mirror.

See [COMPATIBILITY.md](COMPATIBILITY.md), [SECURITY.md](SECURITY.md), [ORIGIN.md](ORIGIN.md), and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## License and attribution

The inherited project remains licensed under [Apache License 2.0](LICENSE). Copyright and attribution for inherited work, the embedded compatibility source, and third-party modules remain with their respective authors and contributors. PastureStack contributors claim authorship only for their own changes.
