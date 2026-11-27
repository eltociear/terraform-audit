#!/usr/bin/env python3
"""terraform-audit - scan Terraform / OpenTofu modules for MALICIOUS code before `terraform plan` runs it.

`terraform plan` is not read-only. A module can run an arbitrary program on your machine while
it *plans*: `data "external"` executes its `program` to compute a value, `data "http"` sends a
request, provider-defined functions run provider code. CI systems run `plan` on every pull
request, often with cloud credentials in the environment. `terraform apply` then runs every
`provisioner "local-exec"` on the operator's machine. `tflint`, `tfsec`, `checkov` and `trivy`
answer "is this infrastructure misconfigured?"; none of them asks "does this module attack the
person running it?". This does: a deterministic (no LLM) static scan for download-and-execute,
environment / credential / state exfiltration, hidden (base64) commands, reverse shells and
persistence - weighted by WHEN the code runs.

Context model:
  plan    data "external" programs, data "http" requests, shell-provider data sources, scripts
          they invoke                                  HIGH -> CRITICAL, MEDIUM -> HIGH
  apply   provisioner "local-exec" (operator machine), scripts it invokes     as scored
  remote  remote-exec, user_data / cloud-init templates (runs on the new VM)  capped at MEDIUM
  deployed  scripts nothing in the module executes locally (Lambda code etc.) capped at MEDIUM
Matches inside HCL comments and `description` strings never score. examples/ and tests/
are skipped unless --all (a consumer of the module never runs them).

The module is never initialised, planned or applied: the source archive is downloaded into
memory and read as text.

Usage:
  python terraform_audit.py <namespace>/<name>/<provider>[@version] [...]  # public registry
  python terraform_audit.py github.com/<owner>/<repo>[?ref=<ref>]          # a GitHub source
  python terraform_audit.py <dir|file.tf|file.tf.json|script.sh>           # local
  python terraform_audit.py --text 'provisioner "local-exec" { command = "curl x | sh" }'
  add --json (family schema) or --sarif (SARIF 2.1.0) for machine-readable output,
  --fail-on {critical,high,medium,low,never}, --version, --verbose to print INFO context,
  --all to include examples/ and tests/

Exit code 2 if any target reaches --fail-on (default HIGH; CI-friendly), 1 on usage errors.
No dependencies beyond the standard library. MIT licensed.
"""
import base64
import bisect
import hashlib
import io
import json
import os
import posixpath
import re
import stat
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

__version__ = "0.2.0"

REGISTRY = os.environ.get("TERRAFORM_AUDIT_REGISTRY", "https://registry.terraform.io").rstrip("/")
HCL_EXT = (".tf", ".tofu")
JSON_EXT = (".tf.json", ".tofu.json")
SCRIPT_EXT = (".sh", ".bash", ".zsh", ".py", ".ps1", ".psm1", ".bat", ".cmd", ".js", ".rb", ".pl")
TEMPLATE_EXT = (".tpl", ".tftpl")
MAX_FILE = 1500000
MAX_TOTAL = 20000000
SKIP_DIR_RE = re.compile(r"(?:^|/)(?:examples?|tests?|test-fixtures|fixtures|docs?|\.github|\.terraform|"
                         r"\.git|\.devcontainer|node_modules|vendor|testdata)/|(?:^|/)(?:test_[^/]*|[^/]*_tests?|tests?)\.(?:py|sh|js|rb)$|"
                         r"(?:^|/)[^/]*\.tftest\.hcl$", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Patterns over command / script text
# ---------------------------------------------------------------------------
EXFIL_HOST = (
    r"(?:discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|"
    r"\bwebhook\.site\b|\bpipedream\.net\b|requestbin\.(?:com|net|io)|\brequestb\.in\b|requestcatcher\.com|beeceptor\.com|"
    r"pastebin\.com/(?:api|raw)|\bpaste\.ee\b|\bhastebin\.com\b|\btransfer\.sh\b|\bfile\.io/|"
    r"\bngrok(?:-free)?\.(?:io|app|dev)\b|\.trycloudflare\.com|\bserveo\.net\b|\blocaltunnel\.me\b|"
    r"\boastify\.com\b|\boast\.(?:fun|me|pro|live|site|online)\b|\binteract\.sh\b|\binteractsh\b|"
    r"\bburpcollaborator\.net\b|\bcanarytokens\.com\b|\bdnslog\.cn\b|\bceye\.io\b|\brequestrepo\.com\b|"
    r"\.workers\.dev\b)"
)
RAW_IP_URL = (r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|"
              r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|2(?:2[4-9]|[3-5]\d)\.))\d{1,3}(?:\.\d{1,3}){3}\b")
# Something that sends/receives over the network from a shell / script.
NET_SEND = (
    r"(?:\bcurl\s|\bwget\s|\bnc(?:at)?\s+-?[\w.]+|\bnetcat\s|Invoke-(?:WebRequest|RestMethod)|\biwr\s|\birm\s|"
    r"Net\.WebClient|\brequests\.(?:get|post|put|request|Session)\s*\(|urllib\.request|urllib2\.|http\.client|"
    r"httpx\.|socket\.(?:create_connection|socket)\s*\(|\.connect\s*\(\s*\(|\bfetch\s*\(|axios|https?\.request\s*\(|"
    r"/dev/(?:tcp|udp)/|Net::HTTP|LWP::|\bopenssl\s+s_client)"
)
UPLOAD_RE = re.compile(r"\bcurl\s[^\n]*(?:\s-d\b|\s--data(?:-\w+)?\b|\s-F\b|\s--form\b|\s-T\b|\s--upload-file\b|-X\s*POST|--request\s+POST)|"
                       r"\bwget\s[^\n]*--post-(?:data|file)|requests\.(?:post|put)\s*\(|Invoke-(?:WebRequest|RestMethod)[^\n]*-Method\s+Post|"
                       r"\bnc(?:at)?\s+[\w.-]+\s+\d+", re.IGNORECASE)
CRED_FILE = (r"(?:\.aws/credentials|\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)|\.terraform\.d/credentials(?:\.tfrc\.json)?|"
             r"\.terraformrc\b|credentials\.tfrc\.json|\.kube/config\b|\.docker/config\.json|"
             r"\.config/gcloud/(?:credentials\.db|application_default_credentials\.json|access_tokens\.db|legacy_credentials)|"
             r"\.azure/(?:accessTokens\.json|msal_token_cache|azureProfile\.json)|\.git-credentials|\.netrc\b|"
             r"\bterraform\.tfstate\b|\.tfstate\b|\.vault-token\b|\.config/gh/hosts\.yml)")
SECRET_ENV = (r"(?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|TF_TOKEN_\w+|ATLAS_TOKEN|TFE_TOKEN|TF_VAR_\w+|"
              r"GITHUB_TOKEN|GH_TOKEN|ARM_CLIENT_SECRET|ARM_ACCESS_KEY|GOOGLE_CREDENTIALS|GOOGLE_APPLICATION_CREDENTIALS|"
              r"VAULT_TOKEN|CLOUDFLARE_API_TOKEN|DIGITALOCEAN_TOKEN|HCLOUD_TOKEN|ACTIONS_RUNTIME_TOKEN|"
              r"ACTIONS_ID_TOKEN_REQUEST_TOKEN|CI_JOB_TOKEN)")
SECRET_ENV_REF = r"(?:\$\{?|os\.environ(?:\.get)?\s*[\[(]\s*['\"]|getenv\s*\(\s*['\"]|\$env:|process\.env\.)" + SECRET_ENV
ENV_DUMP = (r"(?:\$\(\s*(?:env|printenv|export\s+-p)\s*\)|`\s*(?:env|printenv)\s*`|(?:^|[;&|(\s\"'])(?:env|printenv|export\s+-p)\s*(?:\||>(?!\s*&\s*\d|\s*/dev/(?:null|stderr|stdout)))|"
            r"\bjq\s+-n\w*\s+['\"]?\s*(?:env|\$ENV)\s*['\"]?\s*(?:$|[|>\s'\"])|"
            r"(?:dict|json\.dumps|str|repr)\s*\(\s*os\.environ\s*[),]|os\.environ\.(?:items|copy)\s*\(\s*\)\s*\)?\s*[,)]|"
            r"for\s+\w+(?:\s*,\s*\w+)?\s+in\s+os\.environ(?:\.items\(\))?\s*:|"
            r"JSON\.stringify\s*\(\s*process\.env\b|(?:Get-ChildItem|gci|dir|ls)\s+env:\s*(?:\||$))")
B64_REF = re.compile(r"\b(?:base64decode|textdecodebase64)\s*\(\s*(local|var)\.([A-Za-z_][\w-]*)")
B64_LITERAL = re.compile(r"\b(?:base64decode|textdecodebase64)\s*\(\s*\"([A-Za-z0-9+/=\s]{16,})\"")

PATTERNS = {
    "critical": [
        {"id": "download_execute", "name": "Download & Execute",
         "desc": "Fetches remote content and pipes it straight into a shell / interpreter",
         "regexes": [
             r"\bcurl\s+[^\n|;]*\|\s*(?:sudo\s+(?:-\w+\s+)*)?(?:/bin/|/usr/bin/(?:env\s+)?)?(?:sh|bash|zsh|python3?|perl|ruby|node)\b(?!\s*-c\s)",
             r"\bwget\s+[^\n|;]*\|\s*(?:sudo\s+(?:-\w+\s+)*)?(?:/bin/|/usr/bin/(?:env\s+)?)?(?:sh|bash|zsh|python3?|perl|ruby|node)\b(?!\s*-c\s)",
             r"\b(?:ba|z)?sh\s+(?:-\w+\s+)*<\s*\(\s*(?:curl|wget)\b",
             r"\b(?:ba|z)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)\b",
             r"\bpython3?\s+-c\s+[\"']?\$\(\s*(?:curl|wget)\b",
             r"\b(?:iex|Invoke-Expression)\s*\(?\s*\(?\s*(?:New-Object\s+(?:System\.)?Net\.WebClient|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)",
             r"\b(?:exec|eval)\s*\(\s*(?:urllib\.request\.)?urlopen\s*\(",
             r"\b(?:exec|eval)\s*\(\s*requests\.get\s*\(",
         ]},
        {"id": "reverse_shell", "name": "Reverse Shell",
         "desc": "Spawns an interactive shell bound to a network socket",
         "regexes": [
             r"/dev/tcp/[\w.\-${}]+/\d+",
             r"\bbash\s+-i\s*>&",
             r"\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+/bin/(?:ba)?sh",
             r"\bmkfifo\b[^\n]{0,80}\bnc(?:at)?\s",
             r"pty\.spawn\s*\(\s*[\"']/bin/(?:ba)?sh",
             r"os\.dup2\s*\(\s*\w+\.fileno\s*\(\s*\)\s*,\s*[012]\s*\)",
         ]},
        {"id": "destructive", "name": "Destructive Payload",
         "desc": "Wipes the home directory / filesystem of the machine running terraform",
         "regexes": [
             r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(?:--no-preserve-root\s+)?(?:~|\$HOME|\$\{HOME\}|/)(?:/\*)?(?:\s|[\"'`;]|$)",
             r"shutil\.rmtree\s*\(\s*(?:os\.path\.expanduser\s*\(\s*[\"']~[\"']\s*\)|[\"']/[\"'])",
             r"Remove-Item\s+[^\n]*(?:\$env:USERPROFILE|C:\\\\)\s[^\n]*-Recurse",
         ]},
    ],
    "high": [
        {"id": "encoded_exec", "name": "Encoded Command Executed",
         "desc": "Decodes a base64 / compressed blob and executes it - a hidden command",
         "regexes": [
             r"\bbase64\s+(?:-d|--decode|-D)\b[^\n|]*\|\s*(?:sudo\s+)?(?:/bin/)?(?:ba|z)?sh\b",
             r"\|\s*base64\s+(?:-d|--decode|-D)\s*\|\s*(?:sudo\s+)?(?:/bin/)?(?:ba|z)?sh\b",
             r"\becho\s+[\"']?[A-Za-z0-9+/]{40,}={0,2}[\"']?\s*\|\s*base64\s+(?:-d|--decode|-D)",
             r"\bpowershell(?:\.exe)?\b[^\n]{0,60}\s-(?:e|enc|encodedcommand)\s+[\"']?[A-Za-z0-9+/=]{40,}",
             r"\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|zlib\.decompress|codecs\.decode|marshal\.loads|bytes\.fromhex)\s*\(",
             r"\beval\s*\(\s*(?:atob|Buffer\.from)\s*\(",
         ]},
        {"id": "exfil_host", "name": "Exfiltration Endpoint",
         "desc": "Talks to a webhook / paste / tunnel / OAST collector host",
         "regexes": [EXFIL_HOST]},
        {"id": "persistence_write", "name": "Persistence Write",
         "desc": "Writes shell rc files, authorized_keys, cron or launch agents on the machine running terraform",
         "regexes": [
             r">>?\s*[\"']?(?:~|\$HOME|\$\{HOME\})/\.(?:bashrc|zshrc|bash_profile|zprofile|profile)\b",
             r">>?\s*[\"']?(?:~|\$HOME|\$\{HOME\})?/?\.ssh/authorized_keys",
             r"\bcrontab\s+-(?!l\b)[a-z]*\s*[^\n]*",
             r"\(\s*crontab\s+-l[^\n]*\|\s*crontab\s+-",
             r"(?:~|\$HOME)/Library/LaunchAgents/[^\n]*(?:>|cp\s|tee\s)",
             r"\bschtasks\s+/create\b",
         ]},
        {"id": "wallet_browser_theft", "name": "Wallet / Browser / Keychain Theft",
         "desc": "Targets wallet keystores, browser credential stores or the macOS Keychain",
         "regexes": [
             r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad",
             r"(?:Chrome|BraveSoftware|Microsoft/Edge|Opera Software)[^\n]{0,80}(?:Login Data|Local Extension Settings|Cookies)",
             r"\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain)\b",
             r"\b(?:wallet\.dat|seed\.seco)\b|solana/id\.json",
         ]},
        {"id": "dns_exfil", "name": "DNS Exfiltration",
         "desc": "Encodes host / user data into a DNS lookup",
         "regexes": [
             r"\b(?:nslookup|dig|host|ping)\s+(?:-\w+\s+)*[\"']?\$\((?:whoami|hostname|id\b|uname)[^\n]*\)\.[\w-]+\.",
             r"\b(?:nslookup|dig|host)\s+(?:-\w+\s+)*[\"']?\$\{?(?:USER|HOSTNAME|AWS_ACCESS_KEY_ID)\}?\.[\w-]+\.",
         ]},
    ],
    "medium": [
        {"id": "raw_ip_url", "name": "Raw-IP URL",
         "desc": "Contacts a public IP address directly instead of a hostname",
         "regexes": [RAW_IP_URL]},
        {"id": "tls_disabled", "name": "TLS Verification Disabled",
         "desc": "Turns off certificate checking on a download",
         "regexes": [r"\bcurl\s+[^\n]*(?:\s-k\b|\s-\w*k\w*\s|--insecure)", r"\bwget\s+[^\n]*--no-check-certificate",
                     r"verify\s*=\s*False"]},
    ],
    "low": [],
    "info": [
        {"id": "credential_read", "name": "Credential / State File Reference",
         "desc": "References ~/.aws/credentials, ~/.ssh keys, Terraform credentials or state files",
         "regexes": [CRED_FILE]},
        {"id": "secret_env_read", "name": "Secret Environment Variable",
         "desc": "Reads a cloud / CI / Terraform token from the environment",
         "regexes": [SECRET_ENV_REF]},
        {"id": "env_dump", "name": "Environment Dump",
         "desc": "Serialises the whole environment (every token in it)",
         "regexes": [ENV_DUMP]},
        {"id": "network", "name": "Network Access",
         "desc": "Makes outbound HTTP / socket calls",
         "regexes": [NET_SEND]},
        {"id": "base64_decode", "name": "Base64 Decode",
         "desc": "Decodes base64 (often benign: certs, kubeconfigs)",
         "regexes": [r"\bbase64\s+(?:-d|--decode|-D)\b", r"b64decode\s*\(", r"\batob\s*\("]},
    ],
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
SEV_NAMES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_COMPILED = [(sev.upper(), pg, re.compile(rx, re.IGNORECASE)) for sev, groups in PATTERNS.items()
             for pg in groups for rx in pg["regexes"]]
NET_RE = re.compile(NET_SEND, re.IGNORECASE)
EXFIL_RE = re.compile(EXFIL_HOST, re.IGNORECASE)
RAWIP_RE = re.compile(RAW_IP_URL)
CRED_RE = re.compile(CRED_FILE, re.IGNORECASE)
SECRET_ENV_RE = re.compile(SECRET_ENV_REF)
ENV_DUMP_RE = re.compile(ENV_DUMP, re.IGNORECASE | re.MULTILINE)
SH_COMMENT_RE = re.compile(r"^[ \t]*(?:#(?!!)|//|REM\s|::)[^\n]*", re.MULTILINE | re.IGNORECASE)
PY_DOC_RE = re.compile(r"(?:\"\"\"[\s\S]*?\"\"\"|'''[\s\S]*?''')")
NEEDLES = re.compile(r"curl|wget|/dev/|base64|b64|\bnc\b|ncat|netcat|crontab|authorized_keys|bashrc|zshrc|profile|"
                     r"rm\s|rmtree|Remove-Item|iex|Invoke-|eval|exec|http|socket|env|tfstate|credentials|\.ssh|"
                     r"kube|docker|gcloud|azure|netrc|security|wallet|Chrome|Brave|Edge|Opera|nslookup|dig\s|host\s|"
                     r"pty|dup2|mkfifo|schtasks|LaunchAgents|verify|TOKEN|SECRET|KEY|CREDENTIALS|seed|solana|"
                     r"powershell|fetch|axios|requests|urllib|Net::|LWP", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Tolerant HCL scanner (no parser dependency)
# ---------------------------------------------------------------------------
_HEREDOC_RE = re.compile(r"<<(-?)([A-Za-z_][\w-]*)[ \t]*\r?\n")
_SPECIAL = re.compile(r"[\"#/<\n]")
_STR_SPECIAL = re.compile(r"[\"\\$%\n]")


def hcl_lex(text):
    """Return (mask, struct): same length as text.
    mask   = text with comments blanked (strings and heredocs intact)
    struct = mask with string / heredoc CONTENT replaced by 'x' (quotes, braces in code kept),
             so brace / bracket matching on it is structural."""
    n = len(text)
    mask = list(text)
    struct = list(text)
    i = 0

    def blank(a, b, both=True):
        for k in range(a, b):
            if text[k] != "\n":
                struct[k] = " " if both else "x"
                if both:
                    mask[k] = " "

    while i < n:
        m = _SPECIAL.search(text, i)
        if not m:
            break
        i = m.start()
        c = text[i]
        if c == "#" or (c == "/" and text.startswith("//", i)):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif c == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif c == "<":
            hm = _HEREDOC_RE.match(text, i)
            if not hm:
                i += 1
                continue
            ident = hm.group(2)
            start = hm.end()
            em = re.compile(r"^[ \t]*" + re.escape(ident) + r"[ \t]*\r?$", re.MULTILINE).search(text, start)
            end = em.end() if em else n
            body_end = em.start() if em else n
            blank(start, body_end, both=False)
            for k in range(body_end, end):
                if text[k] != "\n":
                    struct[k] = " "
            i = end
        elif c == '"':
            i = _lex_string(text, i + 1, struct)
        else:
            i += 1
    return "".join(mask), "".join(struct)


def _lex_string(text, i, struct):
    """i is just past the opening quote. Marks content 'x' in struct; returns index past closing quote."""
    n = len(text)
    stack = ["S"]  # "S" = in string literal; int = interpolation brace depth
    while i < n and stack:
        top = stack[-1]
        c = text[i]
        if c == "\n":  # quoted strings cannot span lines: recover
            if top == "S" and len(stack) == 1:
                return i
            i += 1
            continue
        if top == "S":
            if c == "\\":
                struct[i] = "x"
                if i + 1 < n and text[i + 1] != "\n":
                    struct[i + 1] = "x"
                i += 2
                continue
            if c == '"':
                stack.pop()
                if not stack:
                    return i + 1
                struct[i] = "x"
                i += 1
                continue
            if c in "$%" and text.startswith("{", i + 1):
                if i + 2 < n and text[i - 1:i] == c:  # $${ is an escape
                    struct[i] = "x"
                    i += 1
                    continue
                struct[i] = struct[i + 1] = "x"
                stack.append(0)
                i += 2
                continue
            struct[i] = "x"
            i += 1
        else:
            struct[i] = "x"
            if c == '"':
                stack.append("S")
            elif c == "{":
                stack[-1] = top + 1
            elif c == "}":
                if top == 0:
                    stack.pop()
                else:
                    stack[-1] = top - 1
            i += 1
    return i


_HEADER_RE = re.compile(r"([A-Za-z_][\w-]*)((?:[ \t]+(?:\"[^\"\n]*\"|[A-Za-z_][\w-]*))*)[ \t]*$")
_LABEL_RE = re.compile(r"\"([^\"\n]*)\"|([A-Za-z_][\w-]*)")


def hcl_blocks(text, struct):
    """All blocks: dicts {type, labels, start, open, close, parent, depth}. Close = index of '}'."""
    blocks, stack = [], []
    pairs = {"}": "{", "]": "[", ")": "("}
    for m in re.finditer(r"[{}\[\]()]", struct):
        c = m.group(0)
        i = m.start()
        if c in "{[(":
            entry = [c, i, None]
            if c == "{":
                ls = struct.rfind("\n", 0, i) + 1
                prefix = struct[ls:i]
                hm = _HEADER_RE.match(prefix.strip())
                if hm and "=" not in prefix and prefix.strip() and not prefix.strip().startswith(("for ", "if ")):
                    off = ls + (len(prefix) - len(prefix.lstrip()))
                    raw = text[off:i]
                    parts = [a or b for a, b in _LABEL_RE.findall(raw)]
                    parent = next((e[2] for e in reversed(stack) if e[2] is not None), None)
                    b = {"type": parts[0], "labels": parts[1:], "start": off, "open": i, "close": len(text) - 1,
                         "parent": parent, "depth": sum(1 for e in stack if e[2] is not None)}
                    blocks.append(b)
                    entry[2] = len(blocks) - 1
            stack.append(entry)
        else:
            while stack and stack[-1][0] != pairs[c]:
                stack.pop()  # tolerate imbalance
            if stack:
                e = stack.pop()
                if e[2] is not None:
                    blocks[e[2]]["close"] = i
    return blocks


_ATTR_RE = re.compile(r"[ \t]*([A-Za-z_][\w-]*)[ \t]*=(?!=)")


def hcl_attrs(text, struct, block):
    """Direct attributes of a block: {name: (value_text, value_start)}."""
    out = {}
    a, b = block["open"] + 1, block["close"]
    i, depth = a, 0
    line_start = True
    while i < b:
        c = struct[i]
        if line_start and depth == 0:
            m = _ATTR_RE.match(struct, i, b)
            if m:
                vs = m.end()
                j, d = vs, 0
                while j < b:
                    cj = struct[j]
                    if cj in "{[(":
                        d += 1
                    elif cj in "}])":
                        d -= 1
                        if d < 0:
                            break
                    elif cj == "\n" and d == 0:
                        # a heredoc's content is 'x' in struct, newlines kept: continue while inside it
                        if not _in_heredoc(text, vs, j):
                            break
                    j += 1
                out.setdefault(m.group(1), (text[vs:j], vs))
                i = j
                line_start = False
                continue
        if c in "{[(":
            depth += 1
        elif c in "}])":
            depth -= 1
        line_start = c == "\n"
        i += 1
    return out


def _in_heredoc(text, vs, j):
    seg = text[vs:j]
    hm = _HEREDOC_RE.search(seg)
    if not hm or seg[:hm.start()].count('"') % 2:
        return False
    ident = hm.group(2)
    return not re.search(r"^[ \t]*" + re.escape(ident) + r"[ \t]*\r?$", seg[hm.end():], re.MULTILINE)


# ---------------------------------------------------------------------------
# Module model
# ---------------------------------------------------------------------------
class TFFile:
    def __init__(self, path, text):
        self.path = path
        self.text = text
        self.nl = [m.start() for m in re.finditer("\n", text)]
        if path.endswith(JSON_EXT):
            self.mask, self.struct, self.blocks = text, text, []
        else:
            self.mask, self.struct = hcl_lex(text)
            self.blocks = hcl_blocks(text, self.struct)

    def line(self, pos):
        return bisect.bisect_right(self.nl, pos - 1) + 1 if pos >= 0 else 0

    def body(self, b):
        return self.mask[b["open"] + 1:b["close"]]

    def attrs(self, b):
        return hcl_attrs(self.mask, self.struct, b)


def _strip_quotes(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def _json_sites(path, text):
    """Pseudo-sites from a .tf.json file."""
    try:
        d = json.loads(text)
    except Exception:
        return [], [], {}
    sites, modules, locals_ = [], [], {}

    def leaves(o):
        if isinstance(o, str):
            yield o
        elif isinstance(o, dict):
            for v in o.values():
                yield from leaves(v)
        elif isinstance(o, list):
            for v in o:
                yield from leaves(v)

    def items(o):
        if isinstance(o, list):
            for x in o:
                yield from items(x)
        elif isinstance(o, dict):
            yield o

    def pos_of(o):
        for s in leaves(o):
            p = text.find(json.dumps(s)[1:-1][:40])
            if p >= 0:
                return p
        return 0
    for blk in items(d.get("data", {})):
        for typ, named in blk.items():
            for nm, body in (named.items() if isinstance(named, dict) else []):
                kind = DATA_EXEC.get(typ)
                if kind:
                    sites.append({"kind": kind, "ctx": "plan", "addr": "data.%s.%s" % (typ, nm),
                                  "text": "\n".join(leaves(body)), "pos": pos_of(body), "attrs": {}})
    for blk in items(d.get("resource", {})):
        for typ, named in blk.items():
            for nm, body in (named.items() if isinstance(named, dict) else []):
                for b in items(body):
                    for prov in items(b.get("provisioner", [])):
                        for pk, pv in prov.items():
                            kind = {"local-exec": "local-exec", "remote-exec": "remote-exec"}.get(pk)
                            if kind:
                                sites.append({"kind": kind, "ctx": "apply" if kind == "local-exec" else "remote",
                                              "addr": "%s.%s" % (typ, nm), "text": "\n".join(leaves(pv)),
                                              "pos": pos_of(pv), "attrs": {}})
    for blk in items(d.get("module", {})):
        for nm, body in blk.items():
            if isinstance(body, dict) and isinstance(body.get("source"), str):
                modules.append((nm, body["source"], body.get("version"), pos_of(body)))
    for blk in items(d.get("locals", {})):
        for k, v in blk.items():
            locals_[k] = "\n".join(leaves(v))
    return sites, modules, locals_


DATA_EXEC = {"external": "external", "http": "http", "shell_script": "shell", "shell_command": "shell",
             "local_command": "shell", "command": "shell", "exec": "shell", "shell": "shell"}
CTX_RANK = {"plan": 4, "apply": 3, "remote": 1, "deployed": 0}
SCRIPT_REF_RE = re.compile(r"([\w./${}\-]*?([\w.\-]+\.(?:sh|bash|zsh|py|ps1|psm1|bat|cmd|js|rb|pl)))\b")
LOCAL_REF_RE = re.compile(r"\blocal\.([A-Za-z_][\w-]*)")
VAR_REF_RE = re.compile(r"\bvar\.([A-Za-z_][\w-]*)")
MUTABLE_REF = re.compile(r"^(?:main|master|develop|dev|trunk|HEAD|latest|release|stable)$")
SECRETISH_VAR = re.compile(r"(?:token|secret|password|passwd|private_key|api_key|apikey|credential|access_key)", re.I)
TF_CRED_EXPR = re.compile(
    r"\b(?:file|filebase64|templatefile|fileset)\s*\(\s*(?:pathexpand\s*\(\s*)?\"[^\"\n]*" + CRED_FILE, re.IGNORECASE)
# a WHOLE external-program result / remote-state output map serialised into a request (an attribute
# such as `.result.token` used as a Bearer header is credential use, not exfiltration)
STATE_REF = re.compile(r"\bdata\.terraform_remote_state\.[\w-]+(?:\[[^\]]*\])?\.outputs\b(?![.\[\w])|"
                       r"\bdata\.external\.[\w-]+(?:\[[^\]]*\])?\.result\b(?![.\[\w])")
NONSENSITIVE_RE = re.compile(r"\bnonsensitive\s*\(")


def _item(sev, pid, name, desc, path, n, matched, ctx_line, kind=None):
    d = {"severity": sev, "id": pid, "name": name, "description": desc, "file": path,
         "line": n, "matched": (matched or "")[:120], "context": (ctx_line or "").strip()[:200]}
    if kind:
        d["context_kind"] = kind
    return d


def _clean_shell(text):
    return SH_COMMENT_RE.sub("", text)


def _match_patterns(text, path, line_of, base_pos, out, kind):
    """Run the shell/script PATTERNS over text. line_of(pos)->line. Appends items; returns id set."""
    if not NEEDLES.search(text):
        return set()
    lines_seen = set()
    ids = set()
    for sev, pg, rx in _COMPILED:
        for m in rx.finditer(text):
            key = (pg["id"], line_of(base_pos + m.start()))
            if key in lines_seen:
                continue
            lines_seen.add(key)
            ls = text.rfind("\n", 0, m.start()) + 1
            le = text.find("\n", m.end())
            le = len(text) if le < 0 else le
            out.append(_item(sev, pg["id"], pg["name"], pg["desc"], path, key[1], m.group(0),
                             text[ls:le], kind))
            ids.add(pg["id"])
            if sev == "INFO":
                break
    return ids


def _combine(local, text, path, line, kind, ids, http_site=False):
    """Combination rules over one execution site / script."""
    has_net = bool(NET_RE.search(text)) or http_site
    exfil = bool(EXFIL_RE.search(text))
    rawip = bool(RAWIP_RE.search(text))
    upload = bool(UPLOAD_RE.search(text)) or http_site
    if "credential_read" in ids and (exfil or rawip or (has_net and upload)):
        local.append(_item("CRITICAL", "credential_exfil", "Credential / State Exfiltration",
                           "Reads a credential store or state file and sends data off-host in the same command/script",
                           path, line, "", "combination", kind))
    if "env_dump" in ids and has_net:
        local.append(_item("CRITICAL", "env_exfil", "Environment Exfiltration",
                           "Dumps the whole environment and talks to the network in the same command/script",
                           path, line, "", "combination", kind))
    if "secret_env_read" in ids and (exfil or rawip):
        local.append(_item("CRITICAL", "secret_env_exfil", "Token Exfiltration",
                           "Reads a cloud/CI/Terraform token from the environment next to an exfil host / raw IP",
                           path, line, "", "combination", kind))
    # exfil host / raw IP with no network sink: a URL in a message
    if not has_net:
        for f in local:
            if f["id"] in ("exfil_host", "raw_ip_url"):
                f["severity"] = "INFO"


def _apply_ctx(items, ctx):
    for f in items:
        s = f["severity"]
        if s == "INFO":
            continue
        if ctx == "plan":
            if s == "HIGH":
                f["severity"] = "CRITICAL"
                f["description"] += " [runs at terraform plan]"
            elif s == "MEDIUM":
                f["severity"] = "HIGH"
                f["description"] += " [runs at terraform plan]"
        elif ctx == "apply":
            f["description"] += " [runs on the operator machine at apply]"
        elif ctx == "remote":
            cap = "LOW" if f["id"] in ("download_execute", "tls_disabled") else "MEDIUM"
            if SEV_ORDER[s] > SEV_ORDER[cap]:
                f["severity"] = cap
                f["description"] += " [runs on the provisioned host, not yours]"
        elif ctx == "deployed":
            cap = "INFO" if f["id"] in ("exfil_host", "raw_ip_url", "tls_disabled") else "MEDIUM"
            if SEV_ORDER[s] > SEV_ORDER[cap]:
                f["severity"] = cap
                f["description"] += " [not executed by terraform]"


def scan_module(files, label="", include_all=False):
    """files: {relative_path: text}. Returns an audit result dict."""
    findings, info = [], []
    total = 0
    tffiles, scripts, templates = {}, {}, {}
    for p in sorted(files):
        if not include_all and SKIP_DIR_RE.search("/" + p):
            continue
        t = files[p]
        if len(t) > MAX_FILE:
            continue
        total += len(t)
        if total > MAX_TOTAL:
            info.append(_item("INFO", "truncated", "Scan Truncated", "Module exceeds %d bytes" % MAX_TOTAL, p, 0, "", ""))
            break
        if p.endswith(JSON_EXT) or p.endswith(HCL_EXT):
            tffiles[p] = TFFile(p, t)
        elif p.endswith(SCRIPT_EXT):
            scripts[p] = t
        elif p.endswith(TEMPLATE_EXT):
            templates[p] = t

    # ---- pass 1: locals, variable defaults, sites, module sources ----------------------
    locals_, var_defaults = {}, {}
    sites, modules = [], []
    for p, f in tffiles.items():
        if p.endswith(JSON_EXT):
            s, mods, loc = _json_sites(p, f.text)
            for x in s:
                x["file"] = f
            sites += s
            modules += [(f, a, b, c, d) for a, b, c, d in mods]
            locals_.update(loc)
            continue
        for b in f.blocks:
            t, labels = b["type"], b["labels"]
            if b["depth"] == 0 and t == "locals":
                for k, (v, _) in f.attrs(b).items():
                    locals_[k] = v
            elif b["depth"] == 0 and t == "variable" and labels:
                a = f.attrs(b)
                if "default" in a:
                    var_defaults[labels[0]] = a["default"][0]
            elif b["depth"] == 0 and t in ("data", "ephemeral") and labels and labels[0] in DATA_EXEC:
                sites.append({"kind": DATA_EXEC[labels[0]], "ctx": "plan", "file": f, "block": b,
                              "addr": "data.%s.%s" % (labels[0], labels[1] if len(labels) > 1 else "?"),
                              "text": f.body(b), "pos": b["open"] + 1, "attrs": f.attrs(b)})
            elif t == "provisioner" and labels and labels[0] in ("local-exec", "remote-exec"):
                parent = f.blocks[b["parent"]] if b["parent"] is not None else None
                addr = ".".join(parent["labels"][:2]) if parent else "?"
                kind = labels[0]
                sites.append({"kind": kind, "ctx": "apply" if kind == "local-exec" else "remote", "file": f,
                              "block": b, "addr": addr, "text": f.body(b), "pos": b["open"] + 1, "attrs": f.attrs(b)})
            elif b["depth"] == 0 and t == "module" and labels:
                a = f.attrs(b)
                if "source" in a:
                    modules.append((f, labels[0], _strip_quotes(a["source"][0]),
                                    _strip_quotes(a["version"][0]) if "version" in a else None, a["source"][1]))
            elif b["depth"] == 0 and t == "action" and labels and re.search(r"local|command|exec|shell", labels[0]):
                # Terraform 1.14 actions that run a local command (hashicorp/local `local_command`)
                sites.append({"kind": "action", "ctx": "apply", "file": f, "block": b,
                              "addr": "action.%s" % ".".join(labels[:2]), "text": f.body(b), "pos": b["open"] + 1,
                              "attrs": f.attrs(b)})

    def expand(text, depth=0, seen=None):
        """Append the values of referenced locals / variable defaults (2 levels)."""
        seen = set() if seen is None else seen
        extra = []
        for rx, table in ((LOCAL_REF_RE, locals_), (VAR_REF_RE, var_defaults)):
            for m in rx.finditer(text):
                k = (rx is LOCAL_REF_RE, m.group(1))
                if k in seen or m.group(1) not in table:
                    continue
                seen.add(k)
                v = table[m.group(1)]
                extra.append(v)
                if depth < 2:
                    extra.append(expand(v, depth + 1, seen))
        return "\n".join(x for x in extra if x)

    def decode_literals(text):
        blobs = [m.group(1) for m in B64_LITERAL.finditer(text)]
        for m in B64_REF.finditer(text):
            v = (locals_ if m.group(1) == "local" else var_defaults).get(m.group(2), "")
            v = _strip_quotes(v)
            if re.fullmatch(r"[A-Za-z0-9+/=\s]{16,}", v):
                blobs.append(v)
        out = []
        for b in blobs:
            try:
                out.append(base64.b64decode(re.sub(r"\s", "", b)).decode("utf-8", "replace"))
            except Exception:
                pass
        return "\n".join(out)

    script_ctx = {}
    by_base = {}
    for p in scripts:
        by_base.setdefault(posixpath.basename(p), []).append(p)

    # ---- pass 2: score each execution site --------------------------------------------
    for s in sites:
        f = s["file"]
        kind, ctx = s["kind"], s["ctx"]
        line = f.line(s["pos"])
        body = s["text"]
        exp = expand(body)
        full = body + ("\n" + exp if exp else "")
        decoded = decode_literals(full)
        full_dec = full + ("\n" + decoded if decoded else "")
        local = []
        slabel = "%s (%s)" % (s["addr"], kind)
        info.append(_item("INFO", {"external": "external_program", "http": "http_data_source", "shell": "shell_data_source",
                                   "local-exec": "local_exec", "remote-exec": "remote_exec", "action": "action"}[kind],
                          {"external": "Plan-Time Program (data \"external\")", "http": "Plan-Time HTTP Request (data \"http\")",
                           "shell": "Plan-Time Shell Data Source", "local-exec": "local-exec Provisioner",
                           "remote-exec": "remote-exec Provisioner", "action": "Action Block"}[kind],
                          "Executes during %s" % ctx, f.path, line, "", s["addr"], ctx))
        if kind == "http":
            a = s.get("attrs", {})
            url = a.get("url", ("", 0))[0]
            req = "\n".join(v for k, (v, _) in a.items() if k in ("url", "request_body", "request_headers"))
            req_full = req + "\n" + expand(req)
            payload = "\n".join(v for k, (v, _) in a.items() if k in ("url", "request_body"))
            payload_full = payload + "\n" + expand(payload)
            dest_bad = EXFIL_RE.search(url) or RAWIP_RE.search(url)
            if NONSENSITIVE_RE.search(payload_full) and not dest_bad:
                local.append(_item("HIGH", "http_nonsensitive", "Sensitive Value Unmasked into data \"http\"",
                                   "nonsensitive() strips the secret marker from a value that is put in a plan-time "
                                   "request URL / body", f.path, line, url[:120], slabel, kind))
            if TF_CRED_EXPR.search(req_full) or STATE_REF.search(payload_full) or \
                    (dest_bad and NONSENSITIVE_RE.search(payload_full)):
                local.append(_item("CRITICAL", "http_secret_exfil", "State / Credential Exfiltration via data \"http\"",
                                   "A plan-time HTTP request carries a credential / state file, a whole remote-state "
                                   "output map or a whole external-program result", f.path, line, url[:120], slabel, kind))
            elif dest_bad:
                pid = "exfil_host" if EXFIL_RE.search(url) else "raw_ip_url"
                local.append(_item("HIGH" if pid == "exfil_host" else "MEDIUM", pid,
                                   "Exfiltration Endpoint" if pid == "exfil_host" else "Raw-IP URL",
                                   "data \"http\" contacts a collector host / raw public IP", f.path, line, url[:120], slabel, kind))
                if any(SECRETISH_VAR.search(v) for v in VAR_REF_RE.findall(req)):
                    local.append(_item("CRITICAL", "http_secret_exfil", "Secret Sent via data \"http\"",
                                       "A secret-named variable is sent to a collector host / raw IP at plan time",
                                       f.path, line, url[:120], slabel, kind))
            if re.search(r"\binsecure\s*=\s*true", body):
                local.append(_item("LOW", "tls_disabled", "TLS Verification Disabled", "data \"http\" with insecure = true",
                                   f.path, line, "", slabel, kind))
        else:
            text = _clean_shell(full_dec)
            nb = len(body)
            ids = _match_patterns(text, f.path, lambda p, t=text: line + t.count("\n", 0, p) if p < nb else line,
                                  0, local, kind)
            for x in local:
                x["context"] = x["context"] or slabel
            _combine(local, text, f.path, line, kind, ids)
            if decoded and kind in ("local-exec", "external", "shell", "action"):
                local.append(_item("HIGH", "hidden_command", "Hidden (base64) Command",
                                   "The command is built by base64decode() of a literal - the real command is hidden from review",
                                   f.path, line, decoded[:120], slabel, kind))
            elif kind in ("local-exec", "external", "shell", "action") and re.search(
                    r"\b(?:command|program|inline)\s*=\s*\[?\s*(?:\"\$\{\s*)?(?:base64decode|textdecodebase64)\s*\(", body + "\n" + exp):
                local.append(_item("HIGH", "hidden_command", "Hidden (base64) Command",
                                   "The command is produced by base64decode() - the real command is hidden from review",
                                   f.path, line, "", slabel, kind))
            # scripts the site invokes
            for m in SCRIPT_REF_RE.finditer(full):
                for sp in _resolve_script(f.path, m.group(1), m.group(2), scripts, by_base):
                    if CTX_RANK[ctx] > CTX_RANK.get(script_ctx.get(sp, ("deployed",))[0], 0):
                        script_ctx[sp] = (ctx, "%s:%d" % (f.path, line))
        _apply_ctx(local, ctx)
        for x in local:
            (info if x["severity"] == "INFO" else findings).append(x)

    # templates rendered into user_data / cloud-init, scripts handed to remote-exec
    for p, f in tffiles.items():
        for m in SCRIPT_REF_RE.finditer(f.mask):
            for sp in _resolve_script(p, m.group(1), m.group(2), scripts, by_base):
                if sp not in script_ctx:
                    script_ctx[sp] = ("deployed", "%s:%d" % (p, f.line(m.start())))

    # ---- pass 3: scripts shipped with the module ----------------------------------------
    for p, t in list(scripts.items()) + list(templates.items()):
        ctx, via = script_ctx.get(p, ("remote" if p.endswith(TEMPLATE_EXT) else "deployed", None))
        text = _clean_shell(t)
        if p.endswith(".py"):
            text = PY_DOC_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
        local = []
        lf = _line_fn(text)
        ids = _match_patterns(text, p, lf, 0, local, ctx)
        nm = NET_RE.search(text)
        _combine(local, text, p, lf(nm.start()) if nm else 1, ctx, ids)
        if via:
            for x in local:
                x["description"] += " (invoked from %s)" % via
        _apply_ctx(local, ctx)
        for x in local:
            (info if x["severity"] == "INFO" else findings).append(x)

    # ---- HCL-level context (never scored above LOW) ---------------------------------------
    for f, name, src, ver, pos in modules:
        sev, why = _module_source_risk(src, ver)
        (findings if sev == "LOW" else info).append(
            _item(sev, "module_source", "Nested Module Source", why, f.path, f.line(pos), src[:120], "module." + name))
    for p, f in tffiles.items():
        for m in re.finditer(r"\bprovider::([\w-]+)::([\w-]+)\s*\(", f.mask):
            info.append(_item("INFO", "provider_function", "Provider-Defined Function",
                              "Calls provider code at plan time: %s" % m.group(0)[:-1], p, f.line(m.start()), m.group(0), ""))
            break
        for m in re.finditer(r"\bsource\s*=\s*\"((?:[\w.-]+/)?[\w-]+/[\w-]+)\"", f.mask):
            src = m.group(1)
            ns = src.split("/")[-2].lower()
            if ns not in ("hashicorp",) and "required_providers" in f.mask[:m.start()] and \
                    f.mask.rfind("module", 0, m.start()) < f.mask.rfind("required_providers", 0, m.start()):
                info.append(_item("INFO", "third_party_provider", "Third-Party Provider",
                                  "Requires a non-HashiCorp provider (its code runs at plan): %s" % src, p,
                                  f.line(m.start()), src, ""))
        for m in TF_CRED_EXPR.finditer(f.mask):
            info.append(_item("INFO", "credential_read", "Credential / State File Read (HCL)",
                              "Reads a credential or state file into the configuration", p, f.line(m.start()), m.group(0), ""))
        for b in f.blocks:
            if b["type"] == "provisioner" and re.search(r"\bwhen\s*=\s*destroy\b", f.body(b)):
                info.append(_item("INFO", "destroy_provisioner", "Destroy-Time Provisioner",
                                  "Runs on terraform destroy", p, f.line(b["start"]), "", ""))
    r = _summarise(findings, info, label)
    r["execution"] = {
        "plan_time": sorted({"%s:%s" % (s["file"].path, s["addr"]) for s in sites if s["ctx"] == "plan"}),
        "apply_time": sorted({"%s:%s" % (s["file"].path, s["addr"]) for s in sites if s["ctx"] == "apply"}),
        "remote": sorted({"%s:%s" % (s["file"].path, s["addr"]) for s in sites if s["ctx"] == "remote"}),
        "scripts_invoked": sorted("%s (%s)" % (p, c[0]) for p, c in script_ctx.items() if c[0] in ("plan", "apply")),
        "nested_modules": len(modules), "tf_files": len(tffiles), "scripts": len(scripts)}
    return r


def _line_fn(text):
    nl = [m.start() for m in re.finditer("\n", text)]
    return lambda pos: bisect.bisect_right(nl, pos - 1) + 1


def _resolve_script(tf_path, ref, base, scripts, by_base):
    d = posixpath.dirname(tf_path)
    rel = re.sub(r"^\$\{\s*path\.(?:module|root|cwd)\s*\}/?", "", ref).lstrip("./") if "${" in ref or ref.startswith("./") else ref
    rel = re.sub(r"\$\{[^}]*\}/?", "", rel)
    for cand in (posixpath.normpath(posixpath.join(d, rel)), posixpath.normpath(rel)):
        if cand in scripts:
            return [cand]
    hits = by_base.get(base, [])
    return hits if len(hits) == 1 else [h for h in hits if posixpath.dirname(h).startswith(d)][:1]


def _module_source_risk(src, ver):
    s = src.strip()
    if s.startswith(("./", "../")):
        return "INFO", "Local submodule"
    if re.match(r"^(?:git::|git@|github\.com/|bitbucket\.org/|https?://[^?]*\.git\b)", s) or "git::" in s:
        ref = urllib.parse.parse_qs(s.split("?", 1)[1]).get("ref", [""])[0] if "?" in s else ""
        if not ref:
            return "LOW", "Git module source with no ?ref= - follows the default branch, content can change under you"
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            return "INFO", "Git module source pinned to a commit"
        if MUTABLE_REF.match(ref):
            return "LOW", "Git module source pinned to a branch (%s) - content can change under you" % ref
        return "INFO", "Git module source pinned to a tag/ref (%s; tags are mutable)" % ref
    if re.match(r"^(?:https?://|s3::|gcs::)", s):
        return "LOW", "Module fetched from an archive URL / bucket - no registry, no version pinning"
    if re.match(r"^(?:[\w.-]+/)?[\w-]+/[\w-]+/[\w-]+(?://.*)?$", s):
        return ("INFO", "Registry module pinned to %s" % ver) if ver else \
               ("INFO", "Registry module with no version constraint - takes whatever is latest")
    return "INFO", "Module source"


def _summarise(findings, info, label):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    score = 0
    for f in findings:
        counts[f["severity"]] += 1
        score += SEVERITY_SCORE[f["severity"].lower()]
    level = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]), "SAFE")
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["file"], f["line"]))
    parts = ["%d %s" % (counts[s], s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]]
    return {"target": label, "risk_score": min(score, 100), "risk_level": level,
            "summary": ", ".join(parts) or "No issues found",
            "findings": findings, "info": info, "total_findings": len(findings), "info_count": len(info)}


def scan(content, label="<text>.tf"):
    """Scan a bare string. HCL unless the label says otherwise; a bare command is treated as a local-exec."""
    if not label.endswith(HCL_EXT + JSON_EXT + SCRIPT_EXT + TEMPLATE_EXT):
        label += ".tf"
    if label.endswith(HCL_EXT) and not re.search(r"^\s*(?:resource|data|module|provisioner|locals|variable|terraform|"
                                                 r"provider|output|ephemeral|action)\b", content, re.MULTILINE):
        content = 'resource "terraform_data" "text" {\n  provisioner "local-exec" {\n    command = <<EOT\n%s\nEOT\n  }\n}\n' % content
    elif label.endswith(HCL_EXT) and re.match(r"\s*provisioner\b", content):
        content = 'resource "terraform_data" "text" {\n%s\n}\n' % content
    return scan_module({label: content}, label, include_all=True)


# ---------------------------------------------------------------------------
# Loading targets (never runs terraform or module code)
# ---------------------------------------------------------------------------
UA = {"User-Agent": "terraform-audit/%s (+https://github.com/eltociear/terraform-audit)" % __version__}
KEEP_RE = re.compile(r"(?:\.tf|\.tofu|\.tf\.json|\.tofu\.json|\.tftpl|\.tpl|\.sh|\.bash|\.zsh|\.py|\.ps1|\.psm1|\.bat|"
                     r"\.cmd|\.js|\.rb|\.pl)$")


def _get(url, timeout=90, tries=4, want_resp=False):
    err = None
    for i in range(tries):
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout)
            return r if want_resp else r.read()
        except urllib.error.HTTPError as e:
            if e.code < 500 and e.code != 429:
                raise
            err = e
        except Exception as e:
            err = e
        time.sleep(2 * (i + 1))
    raise err


def files_from_archive(data, subdir=""):
    out = {}
    sub = subdir.strip("/")
    budget = ArchiveBudget()

    def add(name, read, size=0):
        name = safe_member(name)
        if not name:   # traversal / absolute / drive-letter / NUL member names
            return
        p = name.split("/", 1)[1] if "/" in name else name
        if sub:
            if not p.startswith(sub + "/"):
                return
            p = p[len(sub) + 1:]
        if KEEP_RE.search(p) and budget.take(size):
            out[p] = read().decode("utf-8", "replace")
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            flat = not all("/" in n for n in names)
            for zi in zf.infolist():
                name = safe_member(zi.filename)   # checked before the flat-zip "x/" prefix is added
                if name and not zi.is_dir() and zi.file_size <= MAX_FILE and not stat.S_ISLNK(zi.external_attr >> 16):
                    add(("x/" + name) if flat else name, lambda zi=zi: zf.read(zi), zi.file_size)
        return out
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for m in tf:
            if m.isreg() and m.size <= MAX_FILE:
                fh = tf.extractfile(m)
                if fh:
                    add(m.name, fh.read, m.size)
    return out


def _read_blob(p, cap=500000000):
    with open(p, "rb") as fh:
        return fh.read(cap)


def files_from_dir(root):
    out = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".terraform", ".git", "node_modules")]
        for fn in fns:
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if not KEEP_RE.search(fn) or not regular_file(p):   # symlinks, FIFOs, devices: never opened
                continue
            try:
                if os.path.getsize(p) > MAX_FILE:
                    continue
                with open(p, "rb") as fh:
                    out[rel] = fh.read(MAX_FILE).decode("utf-8", "replace")
            except OSError:
                pass
    return out


def parse_source(src):
    """A go-getter style source -> (kind, url, subdir). kind: github | archive."""
    s = src[5:] if src.startswith("git::") else src
    q = ""
    if "?" in s:
        s, q = s.split("?", 1)
    ref = urllib.parse.parse_qs(q).get("ref", ["HEAD"])[0]
    m = re.match(r"^(?:https?://|ssh://git@|git@)?github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?(?://(.*))?/?$", s)
    if m:
        return "github", "https://codeload.github.com/%s/%s/tar.gz/%s" % (m.group(1), m.group(2), urllib.parse.quote(ref)), \
            (m.group(3) or "")
    sub = ""
    if re.match(r"^https?://", s):
        if "//" in s.split("://", 1)[1]:
            s, sub = s.rsplit("//", 1)
        return "archive", s + ("?" + q if q and "archive=" not in q else ""), sub
    raise ValueError("unsupported module source (only GitHub and HTTP archives are fetched): %s" % src[:100])


def audit_registry(spec, include_all=False):
    name, _, ver = spec.partition("@")
    if ver:
        url = "%s/v1/modules/%s/%s/download" % (REGISTRY, name, urllib.parse.quote(ver))
    else:
        url = "%s/v1/modules/%s/download" % (REGISTRY, name)
    resp = _get(url, want_resp=True)
    xg = resp.headers.get("X-Terraform-Get")
    if not xg:
        raise ValueError("registry gave no X-Terraform-Get for %s" % spec)
    resolved_ver = ver or resp.geturl().rstrip("/").split("/")[-2]
    r = audit_source(xg, include_all, "%s@%s" % (name, resolved_ver))
    r["source"] = xg
    return r


def audit_source(src, include_all=False, label=None):
    kind, url, sub = parse_source(src)
    data = _get(url, timeout=180)
    return scan_module(files_from_archive(data, sub), label or src, include_all)


def _is_registry_spec(a):
    return re.match(r"^[\w.-]+/[\w.-]+/[\w-]+(?:@[\w.+-]+)?$", a) and not a.startswith(("github.com", "./", "../"))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    ex = r.get("execution") or {}
    tag = []
    if ex.get("plan_time"):
        tag.append("plan:%d" % len(ex["plan_time"]))
    if ex.get("apply_time"):
        tag.append("local-exec:%d" % len(ex["apply_time"]))
    print("%s %s  [%s]  score=%d  (%d findings, %d info)%s" % (
        _ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"], r["risk_score"],
        r["total_findings"], r["info_count"], ("  runs-code: " + ",".join(tag)) if tag else ""))
    for f in r["findings"]:
        print("    %-8s %s  %s:%s" % (f["severity"], f["name"], f["file"], f["line"]))
        if f["context"]:
            print("             %s" % f["context"][:160])
    if verbose:
        for f in r["info"]:
            print("    info     %s  %s:%s  %s" % (f["name"], f["file"], f["line"], f["context"][:80]))


# ---------------------------------------------------------------------------
# Pipeline output shared by the eltociear/*-audit family: --json / --sarif / --fail-on
# (this block is kept identical across the family; see "Output formats" in the README)
# ---------------------------------------------------------------------------
FAMILY_SCHEMA = "eltociear-audit/1"
TOOL_NAME = "terraform-audit"
TOOL_URI = "https://github.com/eltociear/terraform-audit"
FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "never")
_FAM_RANK = {"SAFE": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_FAM_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
_FAM_SEC_SEV = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "0.0"}


def family_args(args):
    """Strip the shared output flags from argv. Returns (remaining_args, opts)."""
    opts = {"json": False, "sarif": False, "fail_on": "high"}
    rest, i = [], 0
    while i < len(args):
        a = args[i]
        if a == "--json":
            opts["json"] = True
        elif a == "--sarif":
            opts["sarif"] = True
        elif a == "--fail-on" or a.startswith("--fail-on="):
            if "=" in a:
                v = a.split("=", 1)[1]
            else:
                v = args[i + 1] if i + 1 < len(args) else ""
                i += 1
            if v.lower() not in FAIL_ON_CHOICES:
                sys.stderr.write("%s: --fail-on must be one of %s\n" % (TOOL_NAME, ", ".join(FAIL_ON_CHOICES)))
                raise SystemExit(1)
            opts["fail_on"] = v.lower()
        else:
            rest.append(a)
        i += 1
    return rest, opts


def _fam_sev(s):
    s = str(s or "").upper()
    return s if s in _FAM_RANK else "INFO"


def _fam_line(v):
    try:
        n = int(v)
    except (TypeError, ValueError):
        m = re.search(r"(\d+)\s*$", str(v or ""))
        n = int(m.group(1)) if m else 0
    return n if n > 0 else 0


def family_finding(f, target):
    out = dict(f) if isinstance(f, dict) else {"name": str(f)}
    rid = str(out.get("id") or out.get("rule_id") or out.get("pattern") or "finding")
    out.update({"rule_id": rid, "severity": _fam_sev(out.get("severity")),
                "name": str(out.get("name") or rid), "description": str(out.get("description") or ""),
                "file": str(out.get("file") or out.get("path") or ""), "line": _fam_line(out.get("line")),
                "matched": str(out.get("matched") or ""), "context": str(out.get("context") or "")})
    return out


def family_result(r):
    out = dict(r)
    target = str(out.get("target") or "")
    findings = [family_finding(f, target) for f in (out.get("findings") or [])]
    info = [family_finding(f, target) for f in (out.get("info") or [])]
    worst = max([_FAM_RANK[f["severity"]] for f in findings] + [_FAM_RANK.get(str(out.get("risk_level") or "").upper(), 0)])
    level = next(k for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE") if _FAM_RANK[k] == worst)
    counts = {k: sum(1 for f in findings if f["severity"] == k) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    out.update({"target": target, "risk_level": level, "risk_score": int(out.get("risk_score") or 0),
                "error": out.get("error") or None, "counts": counts, "findings": findings, "info": info})
    return out


def family_exit(results, fail_on="high"):
    """0 = below the threshold, 2 = a target reached it. Default threshold HIGH (the historic behaviour)."""
    if fail_on == "never":
        return 0
    worst = max([_FAM_RANK[family_result(r)["risk_level"]] for r in results] or [0])
    return 2 if worst >= _FAM_RANK[fail_on.upper()] else 0


def family_json(results, fail_on="high"):
    res = [family_result(r) for r in results]
    worst = max([_FAM_RANK[r["risk_level"]] for r in res] or [0])
    return {"schema": FAMILY_SCHEMA, "tool": {"name": TOOL_NAME, "version": __version__},
            "fail_on": fail_on, "exit_code": family_exit(results, fail_on),
            "max_severity": next(k for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE") if _FAM_RANK[k] == worst),
            "errors": sum(1 for r in res if r["error"]), "results": res}


def _fam_uri(target, file):
    """Repo-relative URI when the target is a local path, else the in-package path."""
    file = (file or "").replace("\\", "/")
    t = target or ""
    if t and os.path.isdir(t):
        p = os.path.normpath(os.path.join(t, file)) if file else os.path.normpath(t)
        parts = file.split("/")
        for k in range(1, len(parts)):   # scanner-side prefixes (e.g. custom_components/<d>/) not on disk
            if not os.path.exists(p) and os.path.exists(os.path.join(t, *parts[k:])):
                p = os.path.normpath(os.path.join(t, *parts[k:]))
    elif t and os.path.isfile(t) and (not file or file == t or file == os.path.basename(t)):
        p = os.path.normpath(t)
    elif t and os.path.isfile(t):
        p = os.path.normpath(t).replace("\\", "/") + "/" + file  # member of a local archive
    else:
        p = file or t or "unknown"
    p = p.replace("\\", "/")
    if os.path.isabs(p):
        try:
            rel = os.path.relpath(p)
        except ValueError:
            rel = None
        if rel is not None and not rel.startswith(".."):
            p = rel.replace("\\", "/")
        else:
            return "file://" + urllib.parse.quote(p, safe="/:")
    parts = [s for s in p.split("/") if s not in ("", ".", "..")]
    return urllib.parse.quote("/".join(parts) or "unknown", safe="/@+,;=-._~")


def family_sarif(results):
    rules, index, out, notes = [], {}, [], []
    for r in (family_result(x) for x in results):
        if r["error"]:
            notes.append({"level": "error", "message": {"text": "%s: %s" % (r["target"], r["error"])}})
        for f in r["findings"]:
            sev, rid = f["severity"], f["rule_id"]
            if rid not in index:
                index[rid] = len(rules)
                rules.append({"id": rid, "name": "".join(w.capitalize() for w in re.split(r"[^A-Za-z0-9]+", rid) if w) or "Finding",
                              "shortDescription": {"text": f["name"]},
                              "fullDescription": {"text": f["description"] or f["name"]},
                              "helpUri": TOOL_URI + "#readme",
                              "defaultConfiguration": {"level": _FAM_SARIF_LEVEL[sev]},
                              "properties": {"tags": ["security", TOOL_NAME], "security-severity": _FAM_SEC_SEV[sev]}})
            else:
                rule = rules[index[rid]]
                if float(_FAM_SEC_SEV[sev]) > float(rule["properties"]["security-severity"]):
                    rule["properties"]["security-severity"] = _FAM_SEC_SEV[sev]
                    rule["defaultConfiguration"]["level"] = _FAM_SARIF_LEVEL[sev]
            phys = {"artifactLocation": {"uri": _fam_uri(r["target"], f["file"])}}
            if f["line"]:
                phys["region"] = {"startLine": f["line"]}
                if f["context"]:
                    phys["region"]["snippet"] = {"text": f["context"]}
            msg = "%s: %s%s" % (sev, f["description"] or f["name"], (" [%s]" % f["matched"]) if f["matched"] else "")
            fp = "%s|%s|%s|%s" % (r["target"], rid, f["file"], f["matched"] or f["line"])
            out.append({"ruleId": rid, "ruleIndex": index[rid], "level": _FAM_SARIF_LEVEL[sev],
                        "message": {"text": msg}, "locations": [{"physicalLocation": phys}],
                        "partialFingerprints": {"auditFinding/v1": hashlib.sha256(fp.encode("utf-8", "replace")).hexdigest()[:32]},
                        "properties": {"severity": sev, "target": r["target"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": TOOL_NAME, "version": __version__, "semanticVersion": __version__,
                                          "informationUri": TOOL_URI, "rules": rules}},
                      "invocations": [{"executionSuccessful": not notes, "toolExecutionNotifications": notes}],
                      "results": out}]}


def family_emit(results, opts):
    """Print --json / --sarif output (if requested) and return the process exit code."""
    if opts.get("sarif"):
        print(json.dumps(family_sarif(results), indent=1, ensure_ascii=False))
    elif opts.get("json"):
        print(json.dumps(family_json(results, opts["fail_on"]), indent=1, ensure_ascii=False))
    return family_exit(results, opts["fail_on"])


# ---------------------------------------------------------------------------
# Untrusted-input hygiene shared by the family (nothing is ever extracted to disk)
# ---------------------------------------------------------------------------
MAX_MEMBERS = 50000             # archive entries considered per target
MAX_ARCHIVE_TOTAL = 300000000   # decompressed bytes read per archive (zip/tar bomb budget)


def safe_member(name):
    """Normalise an archive member name; None for traversal (../), absolute, drive or NUL paths."""
    n = (name or "").replace("\\", "/")
    if "\x00" in n or n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        return None
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def regular_file(path):
    """True only for a real regular file (no symlinks, FIFOs, devices or sockets)."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


class ArchiveBudget:
    """Caps entries and total decompressed bytes read from one archive."""

    def __init__(self, total=None, members=None):
        self.left = MAX_ARCHIVE_TOTAL if total is None else total
        self.members = MAX_MEMBERS if members is None else members
        self.truncated = False

    def take(self, size):
        self.members -= 1
        if self.members < 0 or size > self.left:
            self.truncated = True
            return False
        self.left -= size
        return True


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if args[0] == "--version":
        print(TOOL_NAME, __version__)
        return 0
    args, fam = family_args(args)
    as_json = fam["json"] or fam["sarif"]
    verbose = "--verbose" in args or "-v" in args
    include_all = "--all" in args
    args = [a for a in args if a not in ("--json", "--verbose", "-v", "--all")]
    targets = []
    if args and args[0] == "--text":
        txt = " ".join(args[1:])
        targets.append(("<text>", lambda: scan(txt)))
    else:
        for a in args:
            if os.path.isdir(a):
                targets.append((a, (lambda p=a: scan_module(files_from_dir(p), p, include_all))))
            elif os.path.isfile(a):
                if a.endswith((".tar.gz", ".tgz", ".zip", ".tar")):
                    targets.append((a, (lambda p=a: scan_module(files_from_archive(_read_blob(p)), p, include_all))))
                else:
                    targets.append((a, (lambda p=a: scan_module(
                        {os.path.basename(p): _read_blob(p, MAX_FILE).decode("utf-8", "replace")}, p, True))))
            elif _is_registry_spec(a):
                targets.append((a, (lambda s=a: audit_registry(s, include_all))))
            else:
                targets.append((a, (lambda s=a: audit_source(s, include_all))))
    results, worst = [], "SAFE"
    for label, thunk in targets:
        try:
            r = thunk()
        except Exception as e:
            r = {"target": label, "risk_level": "SAFE", "risk_score": 0, "error": str(e)[:200],
                 "findings": [], "info": [], "total_findings": 0, "info_count": 0, "summary": "error"}
            if not as_json:
                print("\u26AA %s  [ERROR] %s" % (label, r["error"]))
        else:
            if not as_json:
                _print(r, verbose)
        results.append(r)
        if SEV_ORDER[r["risk_level"]] > SEV_ORDER[worst]:
            worst = r["risk_level"]
    return family_emit(results, fam)


if __name__ == "__main__":
    sys.exit(main())
