#!/usr/bin/env bash
set -e
SAMPLE="sample.pdf"
OUTDIR="fuzz_in"
NUM=${1:-200}   # antal genererade filer, default 200

mkdir -p "$OUTDIR"
if [ ! -f "$SAMPLE" ]; then
  echo "Lägg en sample.pdf i samma katalog (ett litet giltigt 
PDF-exempel)."
  exit 1
fi

echo "Genererar $NUM muterade filer i $OUTDIR ..."
for i in $(seq 1 $NUM); do
  radamsa "$SAMPLE" > "${OUTDIR}/mut_${i}.pdf"
done
echo "Klar."

