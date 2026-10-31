#!/usr/bin/env bash
# Run the detection benchmark with a transformer NER model.
# Usage: bench/bench_ner.sh monologg/koelectra-base-v3-naver-ner [threshold]
set -euo pipefail
MODEL="${1:?model name required}"; THRESH="${2:-0.5}"
pip install -q "transformers>=4.40" "torch>=2.2"
echo "== rules only =="
axfilter bench
echo "== rules + ${MODEL} =="
axfilter bench --ner-model "$MODEL" --ner-threshold "$THRESH"
