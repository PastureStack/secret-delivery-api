# Security Policy

## Supported migration target

Security review currently covers the PastureStack maintenance commit built from the preserved upstream `v0.2.2` boundary. It is a migration candidate, not a production security claim.

## Runtime requirements

- Bind the API to loopback only. The default is `127.0.0.1:8181`.
- Use a unique 32-byte local key generated and protected by Server. On Unix systems the file must be regular, must not be a symlink, and must not grant group or other permissions.
- Use Vault only with a separately reviewed TLS and token configuration. Plain HTTP remains available solely for loopback test fixtures.
- Keep the insecure `none` backend disabled. Its explicit opt-in exists only for controlled legacy migration and must never protect confidential data.
- Keep debug logging disabled in production. The maintenance layer does not log local key material, HMAC signatures, clear text, or HTTP request and response bodies.
- Restrict filesystem access to key material and do not place keys in images, repositories, or Release assets.
- Verify the GitHub Release asset checksum before installation.

The release gate runs locally and on GitHub for every `main` update and pull request. CodeQL analyzes Go changes and the default branch weekly. Workflow actions are pinned to full commit SHAs, while Dependabot proposes grouped Go-module and workflow-action updates.

## Reporting

Use GitHub private vulnerability reporting for security findings. Do not include active credentials, encryption keys, secret payloads, or production addresses in a public issue.
