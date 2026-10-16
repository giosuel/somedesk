#!/usr/bin/env bash
# Prints the Android versionCode for a version: it has to grow with every release, or phones
# don't take the APK as an update.
#   MAJOR.MINOR.PATCH → ((MAJOR × 1000 + MINOR) × 1000 + PATCH) × 100 + 99
# A pre-release comes before its release: instead of 99 it ends in 0-29 for alpha.N (or other
# names, such as dev.N), 30-59 for beta.N and 60-89 for rc.N (N up to 29). 1.2.3 is 100200399,
# 1.2.3-rc.1 is 100200361. Minor and patch go up to 999, major up to 20 (Android's limit is
# 2100000000).
set -euo pipefail
version="${1:?usage: version-code.sh VERSION}"
re='^([0-9]+)\.([0-9]+)\.([0-9]+)(-([0-9A-Za-z.-]+))?(\+.*)?$'
if ! [[ "$version" =~ $re ]]; then
    echo "version-code.sh: $version is not a version like 1.2.3 or 1.2.3-rc.1" >&2
    exit 1
fi
major=$((10#${BASH_REMATCH[1]})) minor=$((10#${BASH_REMATCH[2]})) patch=$((10#${BASH_REMATCH[3]}))
pre="${BASH_REMATCH[5]}"
if ((major > 20 || minor > 999 || patch > 999)); then
    echo "version-code.sh: $version doesn't fit the versionCode scheme" >&2
    exit 1
fi
if [ -z "$pre" ]; then
    last=99
else
    case "$pre" in
        beta*) base=30 ;;
        rc*) base=60 ;;
        *) base=0 ;;
    esac
    n=0
    [[ "$pre" =~ ([0-9]+)$ ]] && n=$((10#${BASH_REMATCH[1]}))
    if ((n > 29)); then
        echo "version-code.sh: $version: pre-release numbers go up to 29" >&2
        exit 1
    fi
    last=$((base + n))
fi
echo $((((major * 1000 + minor) * 1000 + patch) * 100 + last))
