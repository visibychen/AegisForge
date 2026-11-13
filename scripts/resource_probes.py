"""Fixed trusted resource probes; never accepts or executes user/model code on the host."""

import json
import subprocess
import sys
from uuid import uuid4

from _environment import ROOT, require_conda


def main():
    require_conda()
    sys.path[:0] = [str(ROOT), str(ROOT / "backend")]
    from app.validation.runner import IMAGE, docker_environment

    from evaluation.experiment import write_json

    common = [
        "docker",
        "run",
        "--init",
        "--network",
        "none",
        "--user",
        "65532:65532",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        "128m",
        "--memory-swap",
        "128m",
        "--pids-limit",
        "32",
        "--cpus",
        "1",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
        "--log-driver",
        "none",
        "--entrypoint",
        "python",
    ]
    probes = {
        "memory": "x=bytearray(768*1024*1024); print('unexpected allocation')",
        "pids": """import os,signal,time,json,errno
children=[]
blocked=False
try:
    for _ in range(64):
        try: child=os.fork()
        except OSError as exc:
            blocked=exc.errno==errno.EAGAIN
            break
        if child==0:
            time.sleep(10)
            os._exit(0)
        children.append(child)
    print(json.dumps({'blocked':blocked,'children':len(children)}),flush=True)
finally:
    for child in children:
        try: os.kill(child,signal.SIGTERM)
        except ProcessLookupError: pass
    for child in children:
        try: os.waitpid(child,0)
        except ChildProcessError: pass
""",
        "filesystem": """import json,os,socket
from pathlib import Path
denied=False
try: Path('/candidate-escape').write_text('no')
except OSError: denied=True
Path('/tmp/allowed').write_text('yes')
s=socket.socket();s.settimeout(1)
try: external=s.connect_ex(('1.1.1.1',80))==0
except OSError: external=False
print(json.dumps({'root_write_denied':denied,'tmp_write':Path('/tmp/allowed').read_text()=='yes','socket':Path('/var/run/docker.sock').exists(),'external':external,'uid':os.getuid()}))
""",
    }
    rows = []
    for name, code in probes.items():
        container = "aegisforge-m6-resource-" + uuid4().hex
        try:
            result = subprocess.run(
                [*common, "--name", container, IMAGE, "-c", code],
                env=docker_environment(),
                capture_output=True,
                timeout=20,
                check=False,
            )
            observation = None
            if name == "memory":
                accepted = result.returncode == 137
            else:
                try:
                    observation = json.loads(result.stdout)
                except (ValueError, TypeError):
                    observation = {}
                accepted = result.returncode == 0 and (
                    observation.get("blocked") is True
                    and 1 <= observation.get("children", 999) < 32
                    if name == "pids"
                    else observation
                    == {
                        "root_write_denied": True,
                        "tmp_write": True,
                        "socket": False,
                        "external": False,
                        "uid": 65532,
                    }
                )
            rows.append(
                {
                    "probe": name,
                    "exit_code": result.returncode,
                    "observation": observation,
                    "accepted": accepted,
                }
            )
        except (OSError, subprocess.TimeoutExpired):
            rows.append({"probe": name, "accepted": False, "error": "RESOURCE_ENVIRONMENT"})
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container],
                env=docker_environment(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
            )
    report = {
        "scope": "fixed trusted stress probes; no user/model code",
        "memory_limit_bytes": 128 * 1024 * 1024,
        "pids_limit": 32,
        "rows": rows,
        "passed": all(r["accepted"] for r in rows),
    }
    write_json(ROOT / "data/m6-resources-ci.json", report)
    print(json.dumps(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
