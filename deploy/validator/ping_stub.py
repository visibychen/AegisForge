"""Stand-in for ping inside the validator image (no network exists in the container).

Records its argv for the driver and exits 1 only for the documented unreachable test address.
Invoked through a /bin/sh wrapper installed at /usr/local/bin/ping.
"""

import json
import sys

UNREACHABLE = "192.0.2.77"

with open("/tmp/ping.log", "a", encoding="utf-8") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
raise SystemExit(1 if UNREACHABLE in sys.argv[1:] else 0)
