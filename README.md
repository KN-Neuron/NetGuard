# NetGuard

**A network-change security posture monitor for desktops.**

NetGuard watches for network changes (joining a Wi-Fi network, a new gateway/DNS,
a VPN coming up) and, every time the network changes, runs a battery of
security **posture checks** against the new network. It then renders a
plain-language verdict — **SAFE / CAUTION / UNSAFE** — and notifies the user
through the desktop notification daemon, so people on public Wi-Fi learn
*immediately* whether the network can be trusted with sensitive work.

It is intentionally **dependency-free**: the tool uses only the Python standard
library plus utilities already present on a normal desktop.

---

## The problem

Millions of people connect to café, hotel, airport and conference Wi-Fi every
day. Those networks are exactly where **evil-twin access points, ARP spoofing,
DNS hijacking and TLS interception** happen. The people most at risk — remote
workers handling client data, small organizations without an IT department,
journalists and travellers — rarely have a way to tell whether the network they
just joined is safe until it is too late. Existing advice ("use a VPN") is
generic and arrives before the moment of risk.

**NetGuard targets the moment of risk: the network change itself.**

## What it does

```
Network changes  ─▶  collect link state  ─▶  run 10 posture checks  ─▶  verdict
                                                                         │
                                            notify-send ◀────────────────┘
```

1. **Detects** every network change via NetworkManager events (`nmcli monitor`),
   with a polling fallback that fingerprints the link state.
2. **Collects** the link details: SSID, BSSID, security type, gateway + MAC,
   DNS servers, DHCP server, ARP neighbours, and the surrounding access points.
3. **Runs 10 posture checks** (below) — mixing passive inspection with a small
   number of safe, targeted probes.
4. **Scores** the network and produces a verdict.
5. **Notifies** the user with `notify-send` both *when checks run* and *what the
   verdict is*, and writes a full report (text / JSON / HTML).

## The posture checks

| # | Check | What it detects | Severity |
|---|-------|-----------------|----------|
| 1 | `wifi_encryption` | Open / WEP / WPA1 / TKIP networks | High |
| 2 | `tls_interception` | Active TLS man-in-the-middle (untrusted or private-CA certificates) | Critical |
| 3 | `dns_integrity` | DNS hijacking (answers for non-existent names) and answers that differ from a trusted DoH resolver | High |
| 4 | `arp_gateway` | Gateway MAC changes, spoofed/duplicate ARP entries, gateway impersonation | High |
| 5 | `evil_twin` | Other access points advertising the same SSID with different security | High |
| 6 | `captive_portal` | Captive portals that intercept and redirect traffic | Medium |
| 7 | `proxy_injection` | Transparent HTTP proxies / traffic rewriting | Medium |
| 8 | `router_exposure` | Telnet / UPnP / management ports exposed on the gateway | Medium |
| 9 | `mac_randomization` | Whether your Wi-Fi MAC is randomised (privacy) | Low |
| 10 | `reachability` | Internet egress (context, never scored) | Info |

Checks degrade gracefully: if a probe cannot run (no `requests`, no scan data,
not Wi-Fi, not the local network) the check reports **SKIP** rather than a
false alarm.

## Scoring and verdict

Each failure subtracts a severity-weighted penalty from a 100-point posture
score; warnings cost a fraction of that. Two hard ceilings make severe findings
impossible to average away:

- any **CRITICAL** failure → score capped at 25 → **UNSAFE**
- any **HIGH** failure → score capped at 55 → at best **CAUTION**

| Score | Verdict |
|-------|---------|
| 80–100 | **SAFE** (green) |
| 45–79 | **CAUTION** (amber) |
| 0–44 | **UNSAFE** (red) |

## Install

No Python packages are required.

```bash
# 1. Run straight from the checkout
python3 -m netguard --help

# 2. Or install for the current user + enable the background service
./scripts/install.sh
```

Requirements: Python ≥ 3.9, NetworkManager (`nmcli`), and `notify-send`.
`requests` is optional and only enables the DNS-over-HTTPS comparison in the
DNS integrity check.

## Usage

```bash
# Check the current network once and print a report
netguard check

# Machine-readable output
netguard check --format json

# Watch for network changes; check + notify on every change (the main mode)
netguard watch

# Inspect / debug
netguard state            # current link state as JSON
netguard checks           # list the posture checks

# Write an HTML report
netguard report -o report.html
```

Run as a background service:

```bash
systemctl --user enable --now netguard.service
journalctl --user -u netguard -f
```

## Demo (no hardware required)

The demo swaps only the *probe* layer, so the real check logic, scoring,
notifications and reports all run unchanged. This is how the solution can be
demonstrated on any machine.

```bash
netguard demo --list
netguard demo hotel-mitm --save-html report.html
netguard demo --all            # run every scenario
./run_demo.sh                  # runs all scenarios and writes HTML reports
```

| Scenario | Story | Expected verdict |
|----------|-------|------------------|
| `home-safe` | Well-configured WPA3 home network | SAFE |
| `wired-office` | Conventional wired office link | SAFE |
| `cafe-open` | Open hotspot behind a captive portal | CAUTION |
| `airport-captive` | Open airport Wi-Fi with portal + UPnP | CAUTION |
| `corp-interception` | Managed network with TLS inspection + split-horizon DNS | CAUTION |
| `hotel-mitm` | Open SSID, evil twin, DNS hijack, TLS interception | UNSAFE |

## Project layout

```
netguard/
  cli.py          command-line interface
  monitor.py      network-change detection (nmcli events + polling)
  netstate.py     link-state collection (nmcli/ip/iw/resolvectl)
  probe.py        active probes (DNS, DoH, TLS, HTTP, TCP)
  checks/         the 10 posture checks
  verdict.py      scoring and verdict
  engine.py       orchestration
  notify.py       notify-send notifications + log
  report.py       text / JSON / HTML reports
  store.py        network history for change detection
  demo.py         simulated scenarios
tests/            unit + integration tests (unittest, no dependencies)
scripts/          install.sh, systemd user unit
docs/             presentation (HTML source + generated PDF)
```

## Testing

```bash
python3 -m unittest discover -s tests -t .
```

## Security & privacy notes

- Probes are minimal and non-invasive: TLS handshakes to three well-known hosts,
  DNS lookups, a captive-portal HTTP request, and a short port probe on **your
  own gateway only**. No traffic is captured or stored.
- Only network metadata (SSID/BSSID, gateway, DNS) is persisted, under
  `~/.local/state/netguard/`. Nothing is sent anywhere.
- A blocked probe produces **SKIP**, never a false "unsafe".

## Limitations & roadmap

- Evil-twin detection is heuristic (SSID/security mismatches); a determined
  attacker can clone a network exactly. Roadmap: passive beacon/802.11
  fingerprinting and RTT/latency comparison.
- TLS interception detection trusts the system CA store; a proxy CA installed
  with admin rights is reported as a warning (as intended on managed networks).
- Roadmap: DNS-over-TLS enforcement, per-process connection attribution, a
  tray indicator, and a lightweight agent mode for small-organization fleets.

## License

MIT.
