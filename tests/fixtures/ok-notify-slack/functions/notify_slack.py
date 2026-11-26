import json, os, urllib.request
def handler(event, context):
    url = os.environ["SLACK_WEBHOOK_URL"]  # https://hooks.slack.com/services/...
    req = urllib.request.Request(url, data=json.dumps({"text": str(event)}).encode())
    return urllib.request.urlopen(req).status
