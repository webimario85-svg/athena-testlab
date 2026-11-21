"""Offline-first Athena TestLab CLI: narrow, directly measured tests only."""
import argparse
from pathlib import Path
import sys

from . import __version__
from .evidence import emit
from .manifest import load_manifest, ManifestError, KINDS
from .runner import execute


def build_parser():
    parser = argparse.ArgumentParser(
        prog="athena-testlab",
        description="Read local suite manifests; execute narrow loopback/process checks only.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="action", required=True)
    list_kinds = sub.add_parser("list-kinds", help="List supported observable test kinds")
    run = sub.add_parser("run", help="Run an explicitly supplied local suite")
    run.add_argument("--manifest", type=Path, required=True)
    run.add_argument("--workspace", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True,
                     help="New report directory outside the workspace")
    run.add_argument("--allow-exec", action="store_true",
                     help="Opt into launching workspace-relative executable files (no shell)")
    run.add_argument("--client-exe",
                     help="Workspace-relative Ragexe/client binary for optional case hashing")
    run.add_argument("--server-exe",
                     help="Workspace-relative deployed server binary for optional case hashing")
    run.add_argument("--source-url", default="https://github.com/webimario85-svg/athena-testlab",
                     help="HTTPS provenance reference recorded, never fetched")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.action == "list-kinds":
        for name in sorted(KINDS):
            print(name)
        return 0
    if not args.workspace.is_dir():
        parser.error("--workspace must be an existing directory")
    if args.output.exists():
        parser.error("--output must be a new directory, never an existing one")
    try:
        manifest = load_manifest(args.manifest)
        # Validate optional evidence before any potentially risky test execution.
        if (args.client_exe is None) != (args.server_exe is None):
            parser.error("--client-exe and --server-exe must be provided together")
        if not args.output.parent.is_dir():
            parser.error("--output parent must exist")
        if args.output.resolve().is_relative_to(args.workspace.resolve()):
            parser.error("--output must be outside --workspace")
        if not args.allow_exec and any(t["kind"] == "process-exit"
                                       for t in manifest["tests"]):
            parser.error("process-exit requires explicit --allow-exec")
        from .evidence import file_sha, safe_source
        from .manifest import inside_workspace
        if not safe_source(args.source_url):
            parser.error("--source-url must be a public-style HTTPS URL")
        for path in (args.client_exe, args.server_exe):
            if path is not None:
                file_sha(inside_workspace(args.workspace, path))
        # Ensure all user-supplied executable paths stay under the workspace.
        for test in manifest["tests"]:
            if test["kind"] == "process-exit":
                inside_workspace(args.workspace, test["executable"])
    except ManifestError as err:
        parser.error(str(err))
    outcomes = [execute(test, args.workspace, allow_exec=args.allow_exec)
                for test in manifest["tests"]]
    try:
        report = emit(manifest, outcomes, args.output, args.workspace,
                      client_exe=args.client_exe, server_exe=args.server_exe,
                      source_url=args.source_url)
    except (ManifestError, OSError) as err:
        print(f"Could not create report: {type(err).__name__}", file=sys.stderr)
        return 2
    print(f"Athena TestLab {__version__}: {report['summary']['passed']} passed, "
          f"{report['summary']['failed']} failed; report in {args.output.name}")
    return 1 if report["summary"]["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
