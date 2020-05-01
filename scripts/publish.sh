#!/usr/bin/env bash
set -xeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

(

cd $SCRIPT_DIR

# Get tag
TAGs=($(cat ../pyproject.toml | grep '^version' | awk '{print $3}' | sed -e 's/"//g') )
TAG=v${TAGs[0]}  # we take the first version here
echo $TAG

# Release on Github
git tag $TAG
git push origin $TAG

)