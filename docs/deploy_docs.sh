#!/usr/bin/env bash
set -xeuo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

(
  cd "$SCRIPT_DIR"/..

  echo "Did you verify the examples in the docs work via test_docs_code.sh? - If so type yes"
  read line
  if [[ "$line" != "yes" ]]
  then
    echo "Aborting.."
    exit 1
  fi

  pdoc -o html decentriq_platform
#   this a ugly hack to get rid of the empty index.html site
  cp html/decentriq_platform.html html/index.html

  firebase login
  firebase deploy --only hosting:main
)
