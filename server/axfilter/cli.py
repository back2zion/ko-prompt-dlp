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
    extra = None
    if args.ner_model:
        from .ner_models import TransformerNerRecognizer
        extra = [TransformerNerRecognizer(args.ner_model, threshold=args.ner_threshold)]
        print(f"[bench] using NER model: {args.ner_model} (threshold {args.ner_threshold})")
    print(format_report(score_file(args.dataset, extra=extra)))
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


def _purge(args) -> int:
    import json as _json
    from .app import config_from_env
    from .keys import LocalMasterKeyProvider
    from .store import Store, retention_run
    cfg = config_from_env()
    store = Store(cfg.db_path, cfg.key_provider or LocalMasterKeyProvider(cfg.data_key))
    res = retention_run(store, original_days=cfg.retention_original_days,
                        event_days=cfg.retention_event_days, actor="cli")
    print(_json.dumps(res))
    return 0


def _apikey(args) -> int:
    import json as _json
    from .app import config_from_env
    from .keys import LocalMasterKeyProvider
    from .store import Store
    cfg = config_from_env()
    store = Store(cfg.db_path, cfg.key_provider or LocalMasterKeyProvider(cfg.data_key))
    if args.action == "issue":
        token = store.issue_key(args.name, args.role)
        store.audit("cli", "ISSUE_API_KEY", f"name:{args.name}")
        print(token)   # shown once; store only has its hash
    elif args.action == "revoke":
        ok = store.revoke_key(args.id)
        store.audit("cli", "REVOKE_API_KEY", f"key:{args.id}")
        print("revoked" if ok else "not found or already revoked")
        return 0 if ok else 1
    else:  # list
        print(_json.dumps(store.list_keys(), ensure_ascii=False, indent=2))
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
    s.add_argument("--host", default="0.0.0.0")  # nosec B104 - container bind; nginx terminates TLS in front
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--ssl-certfile")
    s.add_argument("--ssl-keyfile")
    s.set_defaults(fn=_serve)

    sd = sub.add_parser("seed", help="populate synthetic demo data")
    sd.add_argument("days", nargs="?", type=int, default=14)
    sd.set_defaults(fn=_seed)

    b = sub.add_parser("bench", help="score the detector against a labeled dataset")
    b.add_argument("dataset", nargs="?", default="bench/dataset.jsonl")
    b.add_argument("--ner-model", default="", help="HF token-classification model to add (needs axfilter[ner])")
    b.add_argument("--ner-threshold", type=float, default=0.5)
    b.set_defaults(fn=_bench)

    r = sub.add_parser("report", help="generate a compliance evidence report")
    r.add_argument("--period", default="month", choices=["today", "week", "month", "quarter"])
    r.add_argument("--framework", default=None, help="ISMS-P | 'ISO 27001' (default: all)")
    r.add_argument("--csv", action="store_true")
    r.set_defaults(fn=_report)

    pu = sub.add_parser("purge", help="run data retention / purge from env config (no server)")
    pu.set_defaults(fn=_purge)

    ak = sub.add_parser("apikey", help="manage database-backed named API keys")
    aksub = ak.add_subparsers(dest="action", required=True)
    aki = aksub.add_parser("issue", help="issue a named key (prints the raw token once)")
    aki.add_argument("--name", required=True)
    aki.add_argument("--role", required=True, choices=["agent", "viewer", "admin"])
    aki.set_defaults(fn=_apikey)
    akr = aksub.add_parser("revoke", help="revoke a key by id")
    akr.add_argument("--id", type=int, required=True)
    akr.set_defaults(fn=_apikey)
    akl = aksub.add_parser("list", help="list issued keys (no secrets)")
    akl.set_defaults(fn=_apikey)

    sc = sub.add_parser("show-config", help="print resolved settings (secrets redacted)")
    sc.set_defaults(fn=_show_config)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
