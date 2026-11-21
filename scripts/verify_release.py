"""Offline release checks with no source-tree writes except ignored wheel outputs."""
from pathlib import Path
import importlib
import json
import os
import re
import subprocess
import sys
import zipfile


def command(argv, root, env, label):
    result = subprocess.run([sys.executable, *argv], cwd=root, env=env,
                            capture_output=True, encoding="utf-8",
                            errors="replace", timeout=120)
    if result.returncode:
        print(f"{label}=FAIL")
        print("\n".join((result.stdout + result.stderr).splitlines()[-12:]))
        raise SystemExit(1)
    print(f"{label}=PASS")


def main():
    skip_wheel = sys.argv[1:] == ["--skip-wheel"]
    if sys.argv[1:] not in ([], ["--skip-wheel"]):
        raise SystemExit("Use --skip-wheel or no arguments")
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    project = (root / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', project)
    if match is None:
        raise SystemExit("VERSION_METADATA=FAIL")
    version = match.group(1)
    sys.path.insert(0, str(root / "src"))
    if importlib.import_module("athenatestlab").__version__ != version:
        raise SystemExit("VERSION_SYNC=FAIL")
    print(f"VERSION_SYNC=PASS ({version})")
    for doc in sorted((root / "docs").glob("*.json")):
        json.loads(doc.read_text(encoding="utf-8"))
    print("JSON_DOCUMENTS=PASS")
    command(["-B", "-m", "unittest", "discover", "-s", "tests", "-q"],
            root, env, "UNIT_TESTS")
    sources = sorted((root / "src").rglob("*.py")) + sorted((root / "tests").rglob("*.py"))
    for source in sources:
        compile(source.read_bytes(), str(source.relative_to(root)), "exec")
    print(f"PYTHON_SYNTAX=PASS ({len(sources)} files)")
    if skip_wheel:
        print("WHEEL=SKIPPED")
        print("RELEASE_PREFLIGHT=PASS")
        return
    out = root / ".qa" / "release"
    out.mkdir(parents=True, exist_ok=True)
    command(["-m", "pip", "wheel", "--no-index", "--no-deps",
             "--no-build-isolation", "--disable-pip-version-check",
             "--quiet", "-w", str(out), "."], root, env, "WHEEL_BUILD")
    wheels = list(out.glob(f"athena_testlab-{version}-py3-none-any.whl"))
    if len(wheels) != 1:
        raise SystemExit("WHEEL_FILENAME=FAIL")
    with zipfile.ZipFile(wheels[0]) as z:
        contents = z.namelist()
        for suffix in ("athenatestlab/cli.py", "athenatestlab/runner.py",
                       "athenatestlab/evidence.py", "athenatestlab/protocol.py",
                       "athenatestlab/attestation.py", ".dist-info/entry_points.txt"):
            if not any(name.endswith(suffix) for name in contents):
                raise SystemExit("WHEEL_CONTENTS=FAIL " + suffix)
    print("WHEEL_CONTENTS=PASS")
    print("RELEASE_PREFLIGHT=PASS")


if __name__ == "__main__":
    main()
