# Opt-in Bitwarden CLI credential storage

## Status

Approved design, 2026-11-25.

## Context

Users who already keep credentials in Bitwarden or Vaultwarden can opt into
that vault for Pebrel credentials. The OS store remains the default. Existing
callers use the platform credential API, which owns the Pebrel and Nebula
credential names and the order in which those names are read and removed.

## Evidence

- The [platform credential API](../../../../../pebrel_app/src/platform/credentials.rs)
  reads the Pebrel name first and deletes the Nebula fallback first.
- The GPUI SSH editor [checks availability while rendering](../../../../../pebrel_app/src/gpui_shell/ssh_settings/editor.rs)
  and [saves synchronously](../../../../../pebrel_app/src/gpui_shell/ssh_settings.rs).
- Upstream [rbw name lookup](https://github.com/doy/rbw/blob/77464d414a9e41165d5b15f049bee1f0c0f2a982/src/bin/rbw/commands.rs#L2043-L2103)
  can fall back to substring matches. Its [editor adapter](https://github.com/doy/rbw/blob/77464d414a9e41165d5b15f049bee1f0c0f2a982/src/edit.rs#L7-L14)
  reads piped input directly.

## Decision

Settings owns backend parsing, validation and reset. The application resolves
settings and valid environment overrides into one process-level snapshot with
CLI availability. Capability reads use the in-memory snapshot. The CLI owns its
login, unlock state and server configuration, including self-hosted endpoints.

The [CLI adapter](../../../../../pebrel_app/src/platform/credentials/bitwarden.rs)
uses exact name and folder matching. For rbw it parses the JSON listing and
addresses the matched item by UUID. Duplicate matches surface an error.
Credential writes go through stdin. Each command has a 15-second deadline,
drains both output streams and returns diagnostics without echoing CLI output.

## Rejected alternatives

- Calling rbw by name can read, edit or remove a substring match when the
  expected item is absent. This breaks the legacy fallback contract.
- Passing a password in argv exposes it to process inspection. A direct vault
  client would make Pebrel responsible for authentication and protocol behavior.
- Resolving the backend while rendering would put settings and executable
  discovery on the paint path.

## Consequences

Backend, folder and executable settings take effect when Pebrel restarts.
Switching stores does not transfer credentials. An empty folder disables folder
filtering for bw and selects unfiled entries for rbw. A bw save creates a
configured folder when needed. Rbw treats piped input as a password followed by
optional notes, so replacing an rbw password through Pebrel also replaces its notes.

The SSH settings save path already waits synchronously for the system store,
including Linux secret-tool. The accepted backend-only slice retains that
limitation. Multiple CLI calls can extend the wait for a single save. Pebrel
serializes writes in one process. Other vault clients can modify the vault
between listing an item and acting on it.

## Validation

[Settings tests](../../../../../pebrel_settings/src/credentials.rs) cover file
persistence, reset and invalid values. [Adapter tests](../../../../../pebrel_app/src/platform/credentials/bitwarden.rs)
exercise command arguments, stdin, exact and legacy identity matching, and
error redaction. The Unix subprocess test exercises full pipes and timeout cleanup.

## Supersedes

None.

## Revisit when

Move SSH credential saves off the UI thread when the editor can own a pending
save and report its completion. Revisit live configuration reload if users
need to change stores without restarting Pebrel. Recheck the CLI adapters if
upstream changes listing, stdin or UUID dispatch.
