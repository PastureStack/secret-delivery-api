# Compatibility source origin

The `api` package and the `client` schema/resource types preserve the
control-plane wire format used by the inherited service. Their source was
moved without history rewriting from
the Apache-2.0-licensed `github.com/rancher/go-rancher` revision
`2c43ff300f3e304e0205331e809e46cf246fa0b2` (2016-12-20).

PastureStack changed local import paths, removed unused generated client types
and outbound HTTP/WebSocket operations, and made API responses JSON-only so
the service never loads external browser scripts. Copyright and authorship of
the retained source remain with the original contributors.
