"""Command-line entry point: axfilter serve | seed | show-config."""
from __future__ import annotations

import argparse
import sys

from .settings import Settings


def _serve(args) -> int:
    import uvicorn
    from .app import config_from_env, create_app
    app = create_app(config_from_env())
    uvicorn.run(app, host=args.host, port=args.port,
                ssl_certfile=args.ssl_certfile, ssl_keyfile=args.ssl_keyfile)
    return 0


def _seed(args) -> int:
    import runpy
    sys.argv = ["seed_demo.py", str(args.days)]
    runpy.run_path("seed_demo.py", run_name="__main__")
    return 0


def _show_config(args) -> int:
    st = Settings()
    red = st.model_dump()
    for k in ("agent_key", "viewer_key", "admin_key", "data_key", "kms_key_id"):
        if red.get(k):
            red[k] = "***set***"
    for k, v in red.items():
        print(f"{k} = {v}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="axfilter", description="AX Filter server CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the API server")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--ssl-certfile")
    s.add_argument("--ssl-keyfile")
    s.set_defaults(fn=_serve)

    sd = sub.add_parser("seed", help="populate synthetic demo data")
    sd.add_argument("days", nargs="?", type=int, default=14)
    sd.set_defaults(fn=_seed)

    sc = sub.add_parser("show-config", help="print resolved settings (secrets redacted)")
    sc.set_defaults(fn=_show_config)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
