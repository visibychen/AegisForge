"""Read-only checks of the running Compose boundary and fixed validator constraints."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

from _environment import ROOT, require_conda


def main():
    require_conda()
    sys.path.insert(0, str(ROOT / "backend"))
    from app.validation.runner import command, docker_environment

    environment = docker_environment()
    report = {"services": {}, "validator": {}}
    for role in ("api", "worker", "validator"):
        name = "aegisforge-m4-" + role + "-1"
        inspected = subprocess.run(
            ["docker", "inspect", name],
            capture_output=True,
            env=environment,
            timeout=10,
            check=True,
        )
        data = json.loads(inspected.stdout)[0]
        # Only booleans leave this process; Config.Env contents are never printed or saved.
        socket_mount = any(m["Destination"] == "/var/run/docker.sock" for m in data["Mounts"])
        model_key = any(
            v.startswith("AEGISFORGE_DEEPSEEK_API_KEY=") and v.split("=", 1)[1]
            for v in data["Config"].get("Env", [])
        )
        values = {
            "running": data["State"]["Running"],
            "socket_mounted": socket_mount,
            "model_key_present": model_key,
        }
        if role != "validator":
            code = (
                "import json,os,shutil,socket; from pathlib import Path; "
                "s=socket.socket();s.settimeout(1); "
                "print(json.dumps({'uid':os.getuid(),"
                "'docker_cli':shutil.which('docker') is not None,"
                "'socket':Path('/var/run/docker.sock').exists(),"
                "'status':Path('/proc/self/status').read_text(),"
                "'daemon_tcp_accessible':s.connect_ex(('host.docker.internal',2375))==0}))"
            )
            result = subprocess.run(
                ["docker", "exec", name, "python", "-c", code],
                capture_output=True,
                env=environment,
                timeout=10,
                check=True,
            )
            observed = json.loads(result.stdout)
            status = observed.pop("status")
            observed["no_new_privileges"] = "NoNewPrivs:\t1" in status
            observed["capabilities_empty"] = "CapEff:\t0000000000000000" in status
            values.update(observed)
            values["accepted"] = (
                values["running"]
                and not socket_mount
                and observed["uid"] == 1000
                and not observed["docker_cli"]
                and not observed["socket"]
                and not observed["daemon_tcp_accessible"]
                and observed["no_new_privileges"]
                and observed["capabilities_empty"]
            )
        else:
            values["accepted"] = values["running"] and socket_mount and not model_key
        report["services"][role] = values

    ROOT.joinpath("data").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="m4-probe-", dir=ROOT / "data") as directory:
        source = Path(directory) / "candidate.py"
        source.write_text("# fixed infrastructure probe only\n", encoding="utf-8")
        code = """
import json, os, socket
from pathlib import Path
status=Path('/proc/self/status').read_text()
try:
    Path('/candidate.py').write_text('forbidden')
    readonly=False
except OSError:
    readonly=True
s=socket.socket();s.settimeout(1)
print(json.dumps({'uid':os.getuid(), 'candidate_readonly':readonly,
 'interfaces':sorted(p.name for p in Path('/sys/class/net').iterdir()),
 'memory':Path('/sys/fs/cgroup/memory.max').read_text().strip(),
 'pids':Path('/sys/fs/cgroup/pids.max').read_text().strip(),
 'cpu':Path('/sys/fs/cgroup/cpu.max').read_text().strip(),
 'no_new_privileges':'NoNewPrivs:\\t1' in status,
 'capabilities_empty':'CapEff:\\t0000000000000000' in status,
 'docker_socket':Path('/var/run/docker.sock').exists(),
 'external_access':s.connect_ex(('1.1.1.1',443))==0}))
"""
        inspected = subprocess.run(
            ["docker", "image", "inspect", "aegisforge-validator:m4"],
            capture_output=True,
            env=environment,
            timeout=10,
            check=True,
        )
        image = json.loads(inspected.stdout)[0]["Id"]
        run_id = uuid4().hex
        args = command(image, "aegisforge-validation-" + run_id, "xss-01", source.resolve(), run_id)
        index = args.index(image)
        args[index:index] = ["--rm", "--entrypoint", "python"]
        args[-1:] = ["-c", code]
        result = subprocess.run(args, capture_output=True, env=environment, timeout=30, check=True)
        observed = json.loads(result.stdout)
        observed["accepted"] = (
            observed["uid"] == 65532
            and observed["candidate_readonly"]
            and observed["interfaces"] == ["lo"]
            and observed["memory"] == "536870912"
            and observed["pids"] == "128"
            and observed["cpu"] == "100000 100000"
            and observed["no_new_privileges"]
            and observed["capabilities_empty"]
            and not observed["docker_socket"]
            and not observed["external_access"]
        )
        report["validator"] = observed
    report["passed"] = (
        all(v["accepted"] for v in report["services"].values()) and observed["accepted"]
    )
    payload = json.dumps(report, ensure_ascii=False, indent=2)
    ROOT.joinpath("data/m4-isolation.json").write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
