#!/bin/sh
#
# DON'T EDIT THIS!
#
# CodeCrafters uses this file to test your code. Don't make any changes here!
#
# DON'T EDIT THIS!
set -e
tmpFile=$(mktemp)
gcc -Wall -Wextra -Wpedantic -lcurl -lcrypto app/*.c -ggdb -O0 -o $tmpFile
exec gdb --args "$tmpFile" "$@"
