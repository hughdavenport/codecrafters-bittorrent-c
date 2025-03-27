#!/bin/sh
#
# DON'T EDIT THIS!
#
# CodeCrafters uses this file to test your code. Don't make any changes here!
#
# DON'T EDIT THIS!
set -e
tmpFile=$(mktemp)
cc="${CC:-}"
[ -z "$cc" ] && for compiler in tcc gcc clang; do
    [ -z "$cc" ] && cc=$(command -v $compiler) || continue
    break
done
echo "cc = ${cc:-cc}" >&2
CFLAGS="-Wall -Wextra -Wpedantic -Werror"
CFLAGS="$CFLAGS -ggdb"
CFLAGS="$CFLAGS -lcurl -lcrypto"
CFLAGS="$CFLAGS -Wno-gnu-zero-variadic-macro-arguments"
tmpdir=$(mktemp -d)
echo "int main(void) { return 0; }" > "$tmpdir/test.c"
${cc:-cc} -fsanitize=address "$tmpdir/test.c" -o "$tmpFile" 2>/dev/null && CFLAGS="${CFLAGS:-} -fsanitize=address"
rm "$tmpdir/test.c"
rmdir "$tmpdir"
echo "cflags = $CFLAGS" >&2
${cc:-cc} $CFLAGS app/*.c -o "$tmpFile"
exec "$tmpFile" "$@"
