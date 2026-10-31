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


def _bench(args) -> int:
    from .bench import format_report, score_file
    print(format_report(score_file(args.dataset)))
    return 0


def _report(args) -> int:
    import json as _json
    from . import compliance
    from .app import config_from_env
    from .keys import LocalMasterKeyProvider
    from .store import Store
    cfg = config_from_env()
    store = Store(cfg.db_path, cfg.key_provider or LocalMasterKeyProvider(cfg.data_key))
    days = {"today": 1, "week": 7, "month": 30, "quarter": 90}.get(args.period, 30)
    rep = compliance.build_report(
        store, {"key_provider": store.key_provider_name, "tls_required": cfg.require_tls},
        period_days=days, framework=args.framework, sign_key=cfg.data_key)
    print(compliance.to_csv(rep) if args.csv else _json.dumps(rep, ensure_ascii=False, indent=2))
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

    b = sub.add_parser("bench", help="score the detector against a labeled dataset")
    b.add_argument("dataset", nargs="?", default="bench/dataset.jsonl")
    b.set_defaults(fn=_bench)

    r = sub.add_parser("report", help="generate a compliance evidence report")
    r.add_argument("--period", default="month", choices=["today", "week", "month", "quarter"])
    r.add_argument("--framework", default=None, help="ISMS-P | 'ISO 27001' (default: all)")
    r.add_argument("--csv", action="store_true")
    r.set_defaults(fn=_report)

    sc = sub.add_parser("show-config", help="print resolved settings (secrets redacted)")
    sc.set_defaults(fn=_show_config)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
