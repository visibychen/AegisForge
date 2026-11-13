"""Serves the candidate's Flask app on loopback. It holds no verdict logic and, because the
driver starts it with every standard stream closed, cannot reach the driver's result channel."""

import importlib.util
import sys


def main():
    from target_guard import apply_guard

    apply_guard()
    port = int(sys.argv[1])
    spec = importlib.util.spec_from_file_location("candidate", "/candidate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # the candidate's import-time code runs here only
    from werkzeug.serving import make_server

    make_server("127.0.0.1", port, module.app, threaded=False).serve_forever()


if __name__ == "__main__":
    main()
