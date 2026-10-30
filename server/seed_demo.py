"""Populate the DB with synthetic events so the dashboard has data to show.

Usage: AXFILTER_DATA_DIR=data python seed_demo.py [days]
All data is randomly generated; no real personal information is used.
"""
import random
import sys
import time

from axfilter.app import config_from_env
from axfilter.keys import LocalMasterKeyProvider
from axfilter.store import Store

SERVICES = ["chatgpt", "claude", "gemini", "copilot", "perplexity"]
# name, ip range (last octet lo..hi, non-overlapping so IP maps to one group), user count
GROUPS = [
    ("사업본부", 100, 124, 42), ("연구소", 125, 139, 38),
    ("경영관리실", 140, 149, 24), ("전략마케팅실", 150, 169, 15),
]
USERS = [("김민수", "사업수행팀"), ("박서준", "개발1팀"), ("이지은", "QC팀"),
         ("최유리", "개발2팀"), ("정하늘", "영업팀")]
TYPES = ["RRN", "CARD", "PHONE", "EMAIL", "BIZNO", "PASSPORT", "SECRET", "KEYWORD"]


def main():
    days = int(sys.argv[1]) if len(sys.argv) > 1 else 7
    cfg = config_from_env()
    store = Store(cfg.db_path, cfg.key_provider or LocalMasterKeyProvider(cfg.data_key))
    now = int(time.time())
    rnd = random.Random(42)
    total = 0
    for d in range(days):
        day_ts = now - d * 86400
        for _ in range(rnd.randint(2600, 3400)):
            svc = rnd.choices(SERVICES, weights=[8, 5, 4, 2, 1])[0]
            grp, lo, hi, _ = rnd.choices(GROUPS, weights=[42, 38, 24, 15])[0]
            ip = f"192.168.1.{rnd.randint(lo, hi)}"
            user = rnd.choice(USERS)[0]
            ts = day_ts - rnd.randint(0, 86400)
            roll = rnd.random()
            if roll < 0.06:
                action, reason, ftypes = "block", "PII_BLOCKED", rnd.sample(TYPES, k=1)
            elif roll < 0.20:
                action, reason, ftypes = "mask", "PII_MASKED", rnd.sample(TYPES, k=1)
            else:
                action, reason, ftypes = "allow", None, []
            store.add_event(service=svc, user=user, ip=ip, group=grp,
                            direction="input" if rnd.random() < 0.7 else "output",
                            action=action, reason=reason, finding_types=ftypes,
                            latency_ms=rnd.uniform(400, 1400),
                            masked_text="[마스킹됨]" if action != "allow" else "요청",
                            original="합성 데이터", ts=ts)
            total += 1
    print(f"seeded {total} events over {days} days into {cfg.db_path}")


if __name__ == "__main__":
    main()
