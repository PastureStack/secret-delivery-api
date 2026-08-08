# PastureStack Modifications

The single PastureStack maintenance commit after upstream `v0.2.2`:

- changes product-owned package paths, executable identity, documentation, and build output to PastureStack naming;
- retains old protocol and dependency names only inside documented compatibility and legal boundaries;
- replaces obsolete Dapper, Drone, Ubuntu 16.04, Python 2, and GOPATH build plumbing with a Go module workflow fixed to Go 1.26.5;
- replaces the unversioned dependency source tree with `go.mod` and `go.sum`, while retaining only the Apache-2.0 compatibility API, schema, and resource types required by the wire contract;
- removes the unused generated HTTP client, WebSocket dependency, full-body debug logging, and browser HTML writer that loaded unpinned external scripts;
- adds deterministic Release packaging and complete license/source pointers;
- rejects malformed AES-GCM envelopes, RSA keys, signatures, null bulk items, oversized requests, trailing JSON, path-like key names, symlink keys, weak RSA public keys, and arbitrary Vault storage deletion without panicking;
- disables the unencrypted `none` compatibility backend by default, replaces and rejects its weak legacy MD5 signature format, confines local-key reads through `os.Root`, requires protected 32-byte key files, and applies bounded HTTP and Vault timeouts;
- adds race testing, a 70% critical-path coverage gate, Vault protocol tests, complete single and bulk handler tests, reproducible packaging checks, and a loopback local-key API smoke test.

Original authorship remains in the preserved Git history. PastureStack claims authorship only for the maintenance changes in the single commit after the upstream boundary.
