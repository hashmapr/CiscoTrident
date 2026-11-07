#!/bin/sh
# Build the vendored Twofish shared library for Engine A.
# Requires a C compiler (cc/clang/gcc). Run from the repository root.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
CC="${CC:-cc}"
case "$(uname -s)" in
  Darwin) EXT=dylib ;;
  *)      EXT=so ;;
esac
"$CC" -shared -fPIC -O2 -o "$HERE/pka2xml/libtwofish.$EXT" "$HERE/twofish.c"
echo "built $HERE/pka2xml/libtwofish.$EXT"
