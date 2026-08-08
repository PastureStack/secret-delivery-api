# Third-Party Notices

The executable uses the exact Go module graph recorded by `go.mod` and `go.sum`. Copyright, authorship, and license terms remain with the respective projects and contributors.

Direct modules are Gorilla context `v1.1.2`, Gorilla mux `v1.8.1`, HashiCorp Vault API `v1.23.0`, `sirupsen/logrus` `v1.9.4`, and `urfave/cli` `v1.22.17`. Their transitive module graph is recorded in `go.mod` and `go.sum`; those files, rather than this summary, are the authoritative version inventory. The unused Gorilla WebSocket and `pkg/errors` direct dependencies were removed in `v0.3.0`.

The minimum inherited control-plane API, schema, and resource-type source under `compat/controlplane` remains Apache-2.0 licensed. Its exact source revision and modification boundary are recorded in `compat/controlplane/ORIGIN.md`.

GitHub workflows use `actions/checkout` `v7.0.1`, `actions/setup-go` `v7.0.0`, and `github/codeql-action` `v4.37.6`. Every workflow reference is pinned to the exact verified commit recorded inline in the workflow. Dependabot tracks both the Go module graph and these workflow actions in grouped weekly updates.

Release packaging reconstructs the current module source tree with `go mod vendor` in a temporary directory and collects every discovered `LICENSE*`, `COPYING*`, and `NOTICE*` file, plus the project and embedded compatibility-source licenses. The temporary source tree is not committed or included in the binary archive.
