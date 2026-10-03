"""Command-line interface for NetGuard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import APP_NAME, __version__, netstate
from .checks import get_checks
from .config import Config
from .demo import SCENARIOS, get_scenario, list_scenarios, run_scenario
from .engine import run_checks
from .monitor import NetworkMonitor
from .notify import Notifier
from .report import render_html, render_json, render_text
from .store import Store


def _add_global_options(parser: argparse.ArgumentParser, suppress_defaults: bool = False) -> None:
    """Attach the global options.

    ``suppress_defaults`` is used on sub-parsers so that a global option placed
    *after* the sub-command does not reset a value supplied *before* it.
    """

    def add(*args, **kwargs):
        if suppress_defaults:
            kwargs["default"] = argparse.SUPPRESS
        parser.add_argument(*args, **kwargs)

    add("--config", metavar="PATH", help="path to a JSON config file")
    add("--state-dir", metavar="DIR", help="override the state directory")
    add("--no-notify", action="store_true", help="disable desktop notifications")
    add("--interval", type=float, help="poll interval in seconds (polling mode)")
    add("--settle", type=float, help="seconds to let a new link settle")
    add("-v", "--verbose", action="count", help="verbose logging")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netguard",
        description="Monitor network changes and run security posture checks on every new network.",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    _add_global_options(parser)

    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="run the posture checks once on the current network")
    _add_global_options(check, suppress_defaults=True)
    check.add_argument("--format", choices=["text", "json"], default="text")
    check.add_argument("--save-html", metavar="PATH", help="write an HTML report to PATH")

    watch = sub.add_parser("watch", help="monitor for network changes and check each new network")
    _add_global_options(watch, suppress_defaults=True)
    watch.add_argument("--iterations", type=int, default=None,
                       help="stop after N checks (mainly for testing)")

    demo = sub.add_parser("demo", help="run a simulated scenario end-to-end")
    _add_global_options(demo, suppress_defaults=True)
    demo.add_argument("scenario", nargs="?", default="hotel-mitm")
    demo.add_argument("--list", action="store_true", help="list available scenarios")
    demo.add_argument("--all", action="store_true", help="run every scenario")
    demo.add_argument("--format", choices=["text", "json"], default="text")
    demo.add_argument("--save-html", metavar="PATH", help="write an HTML report to PATH")

    state = sub.add_parser("state", help="print the current network state as JSON")
    _add_global_options(state, suppress_defaults=True)

    checks = sub.add_parser("checks", help="list the available posture checks")
    _add_global_options(checks, suppress_defaults=True)

    report = sub.add_parser("report", help="render the last report (or a fresh one) as HTML")
    _add_global_options(report, suppress_defaults=True)
    report.add_argument("--output", "-o", default="netguard-report.html")
    report.add_argument("--fresh", action="store_true",
                        help="run a fresh check instead of using the last report")

    return parser


def _make_logger(verbosity: int):
    def log(message: str) -> None:
        if verbosity:
            print(f"[netguard] {message}", file=sys.stderr)
    return log


def _emit(report, fmt: str) -> None:
    sys.stdout.write(render_json(report) if fmt == "json" else render_text(report))
    sys.stdout.flush()


def cmd_check(args, config: Config, logger) -> int:
    state = netstate.collect()
    if not state.available:
        print("No active network connection detected.", file=sys.stderr)
        return 2
    store = Store(config)
    notifier = Notifier(config)
    if notifier.enabled:
        notifier.notify_start(state)
    report = run_checks(state, config, store=store)
    store.save()
    if args.save_html:
        Path(args.save_html).write_text(render_html(report), encoding="utf-8")
        logger(f"HTML report written to {args.save_html}")
    if notifier.enabled:
        notifier.notify_verdict(report)
    _emit(report, args.format)
    return 0


def cmd_watch(args, config: Config, logger) -> int:
    config.ensure_dirs()
    store = Store(config)
    notifier = Notifier(config)

    def on_change(state):
        if notifier.enabled:
            notifier.notify_start(state)
        report = run_checks(state, config, store=store)
        store.save()
        _emit(report, "text")
        if notifier.enabled:
            notifier.notify_verdict(report)

    monitor = NetworkMonitor(config, on_change, logger=logger)
    print(f"NetGuard watching for network changes · interval {config.interval:g}s · Ctrl-C to stop")
    try:
        monitor.watch(check_initial=True, iterations=args.iterations)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def cmd_demo(args, config: Config, logger) -> int:
    if args.list:
        for scenario in list_scenarios():
            print(f"{scenario.key:18} {scenario.name}\n{'':18} {scenario.summary}")
        return 0

    keys: List[str] = list(SCENARIOS) if args.all else [args.scenario]
    notifier = Notifier(config)
    for key in keys:
        scenario = get_scenario(key)
        if notifier.enabled:
            notifier.notify_start(scenario.state)
        report = run_scenario(key, config)
        if notifier.enabled:
            notifier.notify_verdict(report)
        _emit(report, args.format)
        if args.save_html:
            out = Path(args.save_html)
            if args.all:
                out = out.with_name(f"{out.stem}-{key}{out.suffix or '.html'}")
            out.write_text(render_html(report), encoding="utf-8")
            logger(f"HTML report written to {out}")
    return 0


def cmd_state(args, config: Config, logger) -> int:
    print(json.dumps(netstate.collect().to_dict(), indent=2))
    return 0


def cmd_checks(args, config: Config, logger) -> int:
    for check in get_checks():
        print(f"{check.id:18} {check.title:34} severity={check.severity.value:9} {check.description}")
    return 0


def cmd_report(args, config: Config, logger) -> int:
    if args.fresh or not config.last_report_file.exists():
        state = netstate.collect()
        if not state.available:
            print("No active network connection detected.", file=sys.stderr)
            return 2
        report = run_checks(state, config, store=Store(config))
    else:
        report = json.loads(config.last_report_file.read_text(encoding="utf-8"))
    out = Path(args.output)
    out.write_text(render_html(report), encoding="utf-8")
    print(f"Wrote {out}")
    return 0


_COMMANDS = {
    "check": cmd_check,
    "watch": cmd_watch,
    "demo": cmd_demo,
    "state": cmd_state,
    "checks": cmd_checks,
    "report": cmd_report,
}


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = Config.load(getattr(args, "config", None))
    state_dir = getattr(args, "state_dir", None)
    if state_dir:
        config.state_dir = Path(state_dir)
    interval = getattr(args, "interval", None)
    if interval is not None:
        config.interval = interval
    settle = getattr(args, "settle", None)
    if settle is not None:
        config.settle = settle
    if getattr(args, "no_notify", False):
        config.notify = False
    config.ensure_dirs()

    logger = _make_logger(getattr(args, "verbose", 0) or 0)
    try:
        return _COMMANDS[args.command](args, config, logger)
    except KeyError as exc:
        print(f"No such scenario: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
