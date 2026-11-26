import json, logging, os, sys, hashlib
log = logging.getLogger("package")
def prepare():
    q = json.load(sys.stdin)
    log.debug("ENV: %s", json.dumps(dict(os.environ), indent=2))
    h = hashlib.sha256(q["source_path"].encode()).hexdigest()
    print(json.dumps({"filename": "builds/%s.zip" % h}))
if __name__ == "__main__":
    prepare()
