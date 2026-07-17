# Defguard Object Generator

This crate contains a simple generator for creating users, devices, stats etc during development.

### Database connection

The generator uses the same environment variables (or CLI options) for DB connection setup as the core binary:

- DEFGUARD_DB_HOST
- DEFGUARD_DB_PORT
- DEFGUARD_DB_NAME
- DEFGUARD_DB_USER
- DEFGUARD_DB_PASSWORD

This means that if you have a development environment set up already it should just work.

### Usage

```bash
cargo run -p defguard_generator -- vpn-session-stats \
    --num-users 10 \
    --devices-per-user 2 \
    --sessions-per-device 5

# optional: limit generation to one VPN location --location-id <ID>
```

### Activity log generation

The `vpn-session-stats` command also generates random fake activity log events
(logins, MFA logins, logouts, VPN connect/disconnect, etc.) by default, so the
Activity Log view gets populated without any extra arguments. Event timestamps
are spread over the last minute so they appear as recent activity, and the
activity log table is never truncated, so running the generator repeatedly
(e.g. once per minute) keeps adding fresh events. VPN events are only generated
when at least one VPN location exists.

### Session generation logic

For each device the generator always starts with creating an active (not disconnected) session.
If there are more sessions per device to be generated it goes backwards in time and creates
additional disconnected sessions.
Session duration and gaps between sessions are randomized but there is no logic to verify if
sessions are overlapping so by default the generator runs a `TRUNCATE` query at the start.
To disable this behavior (for example when running it multiple times for separate locations)
use the `--no-truncate` CLI flag.
