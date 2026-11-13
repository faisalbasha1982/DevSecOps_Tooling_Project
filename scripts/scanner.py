"""
scanner.py - run a scanner inside its pinned Docker image (default) or as a
local binary (override). Shared by scan_secrets.py and scan_sast.py.

Docker mode (default)
  docker run --rm --network none --user <uid>:<gid> \
      -v <target>:/scan:ro  -v <config>:/cfg/<name>:ro  -v <tmp>:/out \
      -w /scan  <pinned image> [entry] <args>
  * image tags come from config/images.env - the version pin
  * --network none: the scanner cannot phone home, fetch rules or exfiltrate
    code; it also makes offline behaviour identical to online behaviour
  * the target is mounted read-only; only /out (a private temp dir) is writable
  * the scan runs from /scan with ".", so every reported path is relative

Local mode: set GITLEAKS_BIN / SEMGREP_BIN to a binary (unpinned: results may
differ if its version differs from the pinned image).
"""
from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent

TOOLS = {
    # image entrypoints differ: gitleaks' image runs `gitleaks` itself,
    # semgrep's image needs the `semgrep` command spelled out
    "gitleaks": {"image_var": "GITLEAKS_IMAGE", "bin_var": "GITLEAKS_BIN", "entry": []},
    "semgrep":  {"image_var": "SEMGREP_IMAGE",  "bin_var": "SEMGREP_BIN",  "entry": ["semgrep"]},
}


class ScannerError(Exception):
    pass


def pinned_images() -> Dict[str, str]:
    images = {}
    for line in (ROOT / "config" / "images.env").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            images[k.strip()] = v.strip()
    return images


class Scanner:
    def __init__(self, tool: str, target: Path, config: Path, outdir: Path):
        spec = TOOLS[tool]
        self.tool, self.entry = tool, spec["entry"]
        self.target, self.config, self.outdir = target.resolve(), config.resolve(), outdir
        self.local_bin = os.environ.get(spec["bin_var"])
        self.image = os.environ.get(spec["image_var"]) or pinned_images().get(spec["image_var"])
        if not self.local_bin and not self.image:
            raise ScannerError(f"no image for {tool}: set {spec['image_var']} in config/images.env")
        self.docker = shlex.split(os.environ.get("DOCKER", "docker"))   # e.g. DOCKER="sudo docker"

    @property
    def mode(self) -> str:
        return "local" if self.local_bin else "docker"

    @property
    def ref(self) -> str:
        """What ran - recorded in the artifacts."""
        return f"local:{self.local_bin}" if self.local_bin else self.image

    # Paths as the scanner sees them
    @property
    def config_path(self) -> str:
        return str(self.config) if self.local_bin else f"/cfg/{self.config.name}"

    @property
    def out_path(self) -> str:
        return str(self.outdir) if self.local_bin else "/out"

    def command(self, args: List[str], env: Dict[str, str]) -> List[str]:
        if self.local_bin:
            return [self.local_bin, *args]
        cmd = [*self.docker, "run", "--rm", "--network", "none",
               "--user", f"{os.getuid()}:{os.getgid()}",
               "-e", "HOME=/tmp",
               "-v", f"{self.target}:/scan:ro",
               "-v", f"{self.config}:/cfg/{self.config.name}:ro",
               "-v", f"{self.outdir}:/out",
               "-w", "/scan"]
        for k, v in sorted(env.items()):
            cmd += ["-e", f"{k}={v}"]
        return [*cmd, self.image, *self.entry, *args]

    def run(self, args: List[str], env: Dict[str, str] = None, timeout: int = 600) -> subprocess.CompletedProcess:
        env = env or {}
        cmd = self.command(args, env)
        try:
            return subprocess.run(cmd, cwd=str(self.target), capture_output=True, text=True,
                                  timeout=timeout, env={**os.environ, **env})
        except FileNotFoundError as exc:
            what = self.local_bin if self.local_bin else self.docker[0]
            raise ScannerError(f"'{what}' not found - install Docker (or set "
                               f"{TOOLS[self.tool]['bin_var']} to a local {self.tool})") from exc
        except subprocess.TimeoutExpired as exc:
            raise ScannerError(f"{self.tool} timed out after {timeout}s") from exc

    def version(self) -> str:
        args = ["version"] if self.tool == "gitleaks" else ["--version"]
        proc = self.run(args, env={"SEMGREP_ENABLE_VERSION_CHECK": "0"}, timeout=120)
        if proc.returncode != 0:
            hint = ""
            if "permission denied" in proc.stderr.lower():
                hint = " (Docker permission denied: add yourself to the docker group or set DOCKER='sudo docker')"
            raise ScannerError(f"cannot run {self.ref}{hint}:\n{proc.stderr.strip()[-800:]}")
        return proc.stdout.strip().lstrip("v")

