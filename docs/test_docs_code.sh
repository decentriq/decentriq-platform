#!/usr/bin/env bash
set -xeuo pipefail

python - << 'EOF'
import re
import os

with open("getting_started.md", "r+") as file:
    getting_started = file.read()
    python = re.compile(r'```python\n(.*?)\n```', re.DOTALL)

    code = python.findall(getting_started)
    code = "\n".join(code)
    code = re.sub(r'@@ YOUR TOKEN HERE @@', '95237c6f-98ea-4bfb-bd80-c3399308fee1', code)
    code = re.sub(r'test_user@company.com', r'user_1@decentriq.ch', code)
    code = re.sub(r'Client\(api_token=api_token\)', r'Client(api_token=api_token, client_id="99IeVJ6GHMedQ9RkPNPubpwdWTLgbjY3")', code)
    os.environ['DECENTRIQ_HOST'] = "api-dev.decentriq.ch"
    print("--------\nThis script will run the script against the dev cluster.\n--------")
    exec(code)
EOF
