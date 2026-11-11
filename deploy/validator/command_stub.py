"""Fixed non-networking utilities for registered M6 command injection examples."""

import json
import os
import sys

name = sys.argv[1]
arguments = sys.argv[2:]
with open("/tmp/m6-commands.log", "a", encoding="utf-8") as stream:
    stream.write(json.dumps({"command": name, "argv": arguments, "cwd": os.getcwd()}) + "\n")
if name in {"du", "wc"}:
    print(name + ":" + arguments[-1])
elif name == "pg_dump":
    print("dump:" + arguments[-1])
raise SystemExit(0)
