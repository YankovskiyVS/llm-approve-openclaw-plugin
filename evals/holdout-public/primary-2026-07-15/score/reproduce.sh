#!/bin/sh
set -eu
if [ "$#" -ne 11 ]; then
  echo "usage: $0 INPUT ORACLE FREEZE_COMMITMENT FREEZE_SHA256 FREEZE_RECEIPT RECEIPT_SHA256 INFERENCE INFERENCE_SHA256 PRICING SCORER_GIT_SHA OUTPUT" >&2
  exit 64
fi
exec node ./evals/holdout-score.mjs --input "$1" --oracle "$2" --freeze-commitment "$3" --freeze-commitment-sha256 "$4" --freeze-receipt "$5" --freeze-receipt-sha256 "$6" --inference "$7" --inference-artifact-sha256 "$8" --pricing "$9" --scorer-git-sha "${10}" --output "${11}"
