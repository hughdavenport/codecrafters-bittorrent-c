#!/bin/sh
#
# DON'T EDIT THIS!
#
# CodeCrafters uses this file to test your code. Don't make any changes here!
#
# DON'T EDIT THIS!
set -e
tmpFile=$(mktemp)
CFLAGS=
#CFLAGS="-g -ggdb -fsanitize=address"
gcc $CFLAGS -Wall -Wextra -Wpedantic -lcurl -lcrypto app/*.c -o $tmpFile
exec "$tmpFile" "$@"
