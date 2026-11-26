#!/usr/bin/env python3
"""Reproduce the corpus run behind FINDINGS.md.

1. list:   bulk_scan.py list N top.json             top-N registry modules by downloads (v2 API)
2. fetch:  bulk_scan.py fetch top.json DIR LO HI    resolve X-Terraform-Get, fetch the GitHub tarball into
                                                    memory, keep text files as DIR/NNNN.json.gz
3. scan:   bulk_scan.py scan DIR LO HI OUT.jsonl     each module scanned in its own subprocess (timeout),
                                                    plus a context-free "naive" pass for comparison
Nothing is initialised, planned or applied. Run with python3 -I.
"""
import gzip, io, json, os, re, socket, subprocess, sys, tarfile, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import terraform_audit as ta  # noqa: E402

_orig = socket.getaddrinfo
socket.getaddrinfo = lambda h, p, f=0, *a, **k: _orig(h, p, socket.AF_INET, *a, **k)  # flaky IPv6 here
UA = ta.UA
NAIVE = [(pg["id"], re.compile(rx, re.I)) for sev in ("critical", "high", "medium") for pg in ta.PATTERNS[sev]
         for rx in pg["regexes"]]


def cmd_list(n, out):
    rows, page = [], 1
    while len(rows) < n:
        u = "https://registry.terraform.io/v2/modules?page%%5Bsize%%5D=100&page%%5Bnumber%%5D=%d&sort=-downloads" % page
        d = json.loads(ta._get(u))
        rows += [{"id": m["attributes"]["full-name"], "downloads": m["attributes"]["downloads"]} for m in d["data"]]
        page += 1
        time.sleep(0.5)
    json.dump(rows[:n], open(out, "w"), indent=0)


def cmd_fetch(top, dest, lo, hi):
    rows = json.load(open(top))
    os.makedirs(dest, exist_ok=True)

    def one(i):
        fn = os.path.join(dest, "%04d.json.gz" % i)
        if os.path.exists(fn):
            return
        r = rows[i]
        rec = {"rank": i + 1, "id": r["id"], "downloads": r["downloads"]}
        try:
            resp = ta._get("%s/v1/modules/%s/download" % (ta.REGISTRY, r["id"]), want_resp=True)
            xg = resp.headers.get("X-Terraform-Get") or ""
            rec.update(x_terraform_get=xg, version=resp.geturl().rstrip("/").split("/")[-2])
            kind, url, sub = ta.parse_source(xg)
            rec["files"] = ta.files_from_archive(ta._get(url, timeout=180), sub)
        except Exception as e:
            rec["error"] = str(e)[:200]
        with gzip.open(fn + ".part", "wt") as fh:
            json.dump(rec, fh)
        os.rename(fn + ".part", fn)
    with ThreadPoolExecutor(4) as ex:
        list(ex.map(one, range(lo, hi)))


def scan_one(path):
    rec = json.load(gzip.open(path, "rt"))
    out = {k: rec.get(k) for k in ("rank", "id", "version", "downloads", "x_terraform_get", "error")}
    if "files" not in rec:
        return out
    files = rec["files"]
    r = ta.scan_module(files, rec["id"])
    out.update(level=r["risk_level"], execution=r["execution"],
               findings=[(f["severity"], f["id"], f["file"], f["line"], f.get("context_kind"), f["context"][:160])
                         for f in r["findings"]],
               info_ids=sorted({f["id"] for f in r["info"]}),
               info_ctx=sorted({"%s:%s" % (f["id"], f.get("context_kind")) for f in r["info"]}))
    naive = set()
    for p, t in files.items():
        for pid, rx in NAIVE:
            if pid not in naive and rx.search(t[:2000000]):
                naive.add(pid)
    out["naive"] = sorted(naive)
    out["n_files"] = len(files)
    return out


def _run(paths, timeout):
    try:
        cp = subprocess.run([sys.executable, "-I", os.path.abspath(__file__), "one"] + paths,
                            capture_output=True, text=True, timeout=timeout)
        lines = [l for l in cp.stdout.split("\n") if l.strip()]
        if len(lines) == len(paths):
            return lines
        if len(paths) == 1:
            return [json.dumps({"path": paths[0], "error": "scan crash: " + cp.stderr[-300:]})]
    except subprocess.TimeoutExpired:
        if len(paths) == 1:
            return [json.dumps({"path": paths[0], "error": "scan timeout"})]
    return [l for p in paths for l in _run([p], 300)]  # isolate the bad one


def cmd_scan(d, lo, hi, out, batch=20):
    """Modules are scanned in batches inside a child process with a timeout (a C-level regex
    match can't be interrupted by a signal); a batch that crashes or times out is re-run one
    module per process so a single pathological file is isolated."""
    paths = [os.path.join(d, "%04d.json.gz" % i) for i in range(lo, hi) if os.path.exists(os.path.join(d, "%04d.json.gz" % i))]
    chunks = [paths[i:i + batch] for i in range(0, len(paths), batch)]
    with ThreadPoolExecutor(4) as ex, open(out, "w") as fh:
        for lines in ex.map(lambda c: _run(c, 900), chunks):
            for line in lines:
                fh.write(line + "\n")


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[0] == "list":
        cmd_list(int(a[1]), a[2])
    elif a[0] == "fetch":
        cmd_fetch(a[1], a[2], int(a[3]), int(a[4]))
    elif a[0] == "one":
        for p in a[1:]:
            print(json.dumps(scan_one(p)), flush=True)
    elif a[0] == "scan":
        cmd_scan(a[1], int(a[2]), int(a[3]), a[4])
