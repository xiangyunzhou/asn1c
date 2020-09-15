#!/usr/bin/env sh
set -ex

cwd=$(pwd)
type=$(basename "$0" | rev | cut -c4- | rev | cut -c7- | tr _ " ")

rm -rf "test-${type}"
mkdir "test-${type}"
cd "test-${type}"
"${cwd}/check-asn1c-smoke.sh" "${type}"
