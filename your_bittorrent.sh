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
for compiler in tcc gcc clang; do
    [ -z "$cc" ] && cc=$(command -v $compiler) || continue
    echo "cc = $cc"
    break
done
${cc:-cc} -Wall -Wextra -Wpedantic -Werror -Wno-gnu-zero-variadic-macro-arguments -fsanitize=address -ggdb -lcurl -lcrypto app/*.c -o "$tmpFile"
exec "$tmpFile" "$@"
