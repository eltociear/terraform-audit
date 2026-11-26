# What we found scanning the 1,700 most-downloaded Terraform registry modules

This is the research behind `terraform-audit`: a scan of the top of the public Terraform
Registry, run with this exact engine. The rules were calibrated on one set, frozen in a git
commit, and then run once on a separate held-out set. Same method as
[mcp-audit](https://github.com/eltociear/mcp-audit/blob/main/FINDINGS.md),
[npm-audit](https://github.com/eltociear/npm-audit/blob/main/FINDINGS.md) and
[crate-audit](https://github.com/eltociear/crate-audit/blob/main/FINDINGS.md).

## Method

1. Listed the top 1,700 modules by all-time downloads from the registry's v2 API
   (`/v2/modules?sort=-downloads`). They range from 449.7M downloads at rank 1 to 22.8K at rank 1,700.
2. For each module, asked the registry where its latest version lives
   (`/v1/modules/<ns>/<name>/<provider>/download` gives an `X-Terraform-Get` header). Every one
   of the 1,689 resolvable modules pointed at a GitHub repository **pinned to a commit SHA**. We
   fetched that commit's tarball from `codeload.github.com` into memory and kept only the text
   files: `.tf`, `.tf.json`, templates and scripts. Nothing was initialised, planned or applied.
3. Scanned each module in a child process with a timeout. `examples/`, `test(s)/`, `docs/`,
   `.github/`, `.devcontainer/`, `*.tftest.hcl` and test-named scripts were skipped, because a
   consumer of the module never runs them.
4. **Calibration set:** ranks 1-1,000. 994 were scanned; 4 registry entries point at deleted
   repositories (404) and 2 failed on a flaky network after retries. **Held-out set:** ranks
   1,001-1,700. 695 were scanned and 5 returned 404. The rules were frozen in commit `a78087e`
   before the held-out set was scanned once.
5. The **naive pass** for comparison: every CRITICAL / HIGH / MEDIUM regex run over every file's
   raw text. No HCL parsing, no execution-site model, no comment / example / context handling.

The HCL scanner was also checked for structural errors. Across the 22,314 `.tf` files in the
first 650 modules, every file's braces balanced after string, heredoc and comment handling,
and no block was left unclosed.

Scan date: 2026-11-26.

## Headline

| Result | Calibration (994) | Held-out (695) |
| --- | --- | --- |
| Naive pass, any CRITICAL/HIGH/MEDIUM pattern | 27 (2.7%) | 23 (3.3%) |
| `terraform-audit`, first pass, HIGH+ | 1 (0.10%) | — |
| `terraform-audit`, frozen rules, HIGH+ | **0** | **0 (0.0%)** |
| `terraform-audit`, frozen rules, MEDIUM | 3 | 4 |
| `terraform-audit`, frozen rules, LOW | 9 | 2 |
| After the two post-blind fixes below: HIGH+ / MEDIUM / LOW | 0 / 3 / 9 | 0 / 3 / 2 |

**The held-out set scored 0 HIGH or CRITICAL on its one blind run.** Neither set had a
module that a human reviewer would call malicious. A CRITICAL on a module you have never heard
of means something only if the 1,689 modules everyone already uses don't trip it.

The one calibration false positive was a vendor module whose `data "external"` helper returns
API credentials, and whose `data "http"` sends one attribute of that result as a Bearer token
to the vendor's own API. The first rule treated any `data.external.*.result` in a request as
exfiltration. It now fires only when the **whole** result object (or a whole
`terraform_remote_state` outputs map) is serialised into the URL or body. A single attribute in
an `Authorization` header is credential use, and has a benign test fixture.

Two held-out bugs were fixed **after** the blind run. Neither changes a HIGH+ number:

- A test file named `tests.py` (no underscore) beside a notification Lambda was scanned as
  deployed code. Its env-dump plus HTTP mock produced one of the 4 held-out MEDIUMs. Test-file
  skipping now includes `test.py` / `tests.py`.
- `file("~/.ssh/id_rsa.pub")` matched the private-key path pattern. That was INFO only. Public
  keys are now excluded.

## How much of the registry runs code on your machine

| | Calibration (994) | Held-out (695) |
| --- | --- | --- |
| Runs **any** local code (plan or apply) | 106 (10.7%) | 64 (9.2%) |
| Runs code **at plan time** (`data "external"` / `http` / shell data source) | 53 (5.3%) | 28 (4.0%) |
| `data "external"`: arbitrary program at plan | 32 (3.2%) | 13 (1.9%) |
| `data "http"`: outbound request at plan | 23 (2.3%) | 16 (2.3%) |
| `provisioner "local-exec"`: operator machine at apply | 66 (6.6%) | 45 (6.5%) |
| Ships scripts that a local-exec / external program invokes | 38 (3.8%) | 22 (3.2%) |
| Destroy-time provisioners | 16 (1.6%) | 9 (1.3%) |
| `remote-exec` (runs on the new VM) | 11 (1.1%) | 6 (0.9%) |
| Calls provider-defined functions | 61 (6.1%) | 22 (3.2%) |
| Requires a non-HashiCorp provider | 287 (28.9%) | 172 (24.7%) |
| Pulls in nested modules | 519 (52.2%) | 278 (40.0%) |

**About one in twenty popular modules runs a program while you `terraform plan`.** That
program runs on a developer laptop or a CI runner, before any review of the plan output. A
plan-on-PR workflow runs it on every pull request. The most common legitimate uses are
packaging (one very popular Lambda module runs a Python packager at plan time), reading the
caller's identity through the cloud CLI, computing OIDC thumbprints with `openssl s_client`,
and polling a vendor API with `curl`.

### What plan- and apply-time code actually does

| Capability seen inside local-run code (calibration) | Modules | |
| --- | --- | --- |
| `curl` / HTTP from local-exec or an invoked script | 17 | Downloading release zips for Lambdas, vendor API calls (install an app, register a cluster), health checks |
| Network from a plan-time program | 5 | Vendor API lookups, version lists |
| `base64 -d` in local-exec | 5 | Decoding kubeconfigs / CA certs for `kubectl`, signing a GitHub App JWT |
| Reads a token env var (`ARM_CLIENT_SECRET`, `GOOGLE_APPLICATION_CREDENTIALS` …) | 2 | Checking it is set before calling the cloud CLI |
| Dumps the whole environment | 1 | A packager's debug log line (a tunnel script's `env >&2` matched too, until stderr prints were excluded) |
| **Sends an env dump, a credential file or state anywhere** | **0** | |
| **Pipes a download into a shell on the operator's machine** | **0** | (it happens on provisioned VMs - see below) |

## The noise: what looks dangerous but isn't

The naive pass flagged 50 of 1,689 modules (3.0%). Every one was a false positive:

| Signal | Where it came from | Why it's noise |
| --- | --- | --- |
| Slack / Discord webhook hosts (32 files) | `examples/`, test files, notifier Lambda source | Placeholder `hooks.slack.com/services/AAA/BBB/CCC` URLs, and Lambdas whose *job* is to post to Slack. They run in the cloud with a webhook the user supplied |
| `curl … \| bash` (12 files) | `user_data` / startup templates, Makefiles, packer files, test installers | Installing the logging agent or GitLab runner **on the VM being created**. That is a supply-chain smell for the VM, not an attack on the operator |
| TLS verification off (25 files) | `ssl_verify = false` in `.tftest.hcl`, Helm `verify = false`, `curl -k` health checks against a just-created cluster | Self-signed endpoints the module itself created |
| `>> ~/.bashrc`, `crontab`, `schtasks` (11 files) | `.devcontainer/` setup, startup templates, Windows examples | Developer containers and VM boot scripts |
| Raw-IP URLs (2 files) | TEST-NET addresses in test harnesses | Documentation addresses |

Everything here is a **capability or a VM-side install**, not an attack on the person running
`terraform`. The context model accounts for every row:

- Only execution sites are scored in `.tf` files, so a URL in a variable `description` or
  `default` never scores.
- Templates and `remote-exec` run on the provisioned host and are capped at MEDIUM
  (`curl | sh` at LOW).
- Scripts nothing runs locally are capped at MEDIUM, and collector hosts in them drop to INFO.
- Examples, tests and dev-container setup are skipped.

What remains at MEDIUM after calibration: `curl -k` / `wget --no-check-certificate` health
checks in local-exec, a startup template installing a cron job, and a CI-runner boot template that
installs an SSH key pair on the VM and registers the runner with a POST. Those are worth a glance, not an alarm.

## Known incidents, and the shape each one has

**No confirmed malicious module on the public Terraform Registry has been publicly reported,
as far as we know.** The risk here is documented mostly by research and demonstrations. The
canaries in `tests/fixtures/` (inert hosts, `CANARY` strings) model those shapes:

- **"`terraform plan` is RCE" write-ups.** Several security write-ups show that `plan` on an
  untrusted change executes code: a `data "external"` program, a malicious provider, or a
  provider-defined function. This matters most where CI runs `plan` on pull requests. Canaries:
  `mal-plan-env-exfil` (`env | base64` POSTed from `program`), `mal-plan-script-cred` (the
  program is a shipped `account.sh` that reads `~/.aws/credentials` and uploads it; the script
  is scored in **plan** context because the external data source invokes it),
  `mal-plan-python-env` (`dict(os.environ)` POSTed by a Python helper) and `mal-tf-json` (the
  same in `.tf.json` syntax). All score CRITICAL.
- **State / credential exfiltration through `data "http"`.** This needs no shell. A plan-time
  GET whose URL carries `base64encode(file("terraform.tfstate"))`
  (`mal-http-state-exfil`), a request body built from `file(pathexpand("~/.aws/credentials"))`
  through a local (`mal-http-cred-exfil`), or an `external` env dump chained into an `http` URL
  (`mal-http-external-chain`). All CRITICAL.
- **local-exec `curl | sh`** on the operator's machine (`mal-localexec-curl-sh`): CRITICAL.
- **Hidden base64 command.** `command = base64decode(local.setup)`, where the local is a
  base64 literal (`mal-b64-hidden-command`). The literal is decoded and scanned as the command
  it really is (`curl … | sh`, so CRITICAL), plus a separate `hidden_command` finding. Also
  `echo <b64> | base64 -d | sh` (`mal-b64-pipe-sh`): HIGH.
- **Malicious-module demonstrations.** A module that phones home with `TF_TOKEN_*` to a webhook
  collector (`mal-token-exfil`), opens a reverse shell from local-exec (`mal-revshell`), or
  plants a `~/.bashrc` line (`mal-persist`).

Nine benign controls cover what the noise table shows real modules doing. They include a
plan-time Lambda packager that logs its environment, `curl | sh` in `remote-exec` and
`user_data`, a Slack-notifier Lambda, kubectl-from-local-exec with tricky heredoc
interpolation, `checkip` / GitHub API `data "http"` with a token header, an external
credential helper whose single attribute becomes a Bearer header, an `openssl s_client`
thumbprint script, pinned module sources, and a malicious snippet that lives only in
`examples/`. They must stay SAFE (or LOW for the VM-side install).

## Takeaways

1. **`terraform plan` runs third-party code in about 5% of popular modules.** Treat
   `plan` on an untrusted change like running a build of it. Do not give plan-on-PR jobs
   credentials beyond read-only, and scan changed modules first:
   `terraform_audit.py ./modules/x` or `terraform_audit.py ns/name/provider@new-version`.
2. **The registry pins each published version to a commit, but nested modules don't have to.**
   Every registry download we resolved was SHA-pinned. Inside modules, `git::…` sources with no
   `ref` or with a branch ref still appear (LOW). Those can change under you between two `init`s.
3. **`data "http"` is an exfiltration channel that needs no shell.** A scanner that only looks
   for `curl` misses it. `terraform-audit` follows locals and variable defaults into the
   request.
4. **Most of what looks scary runs on the VM, not on you.** `curl | bash` in `user_data` is
   everywhere and is not an attack on the operator. Scoring it as one would flag the modules
   everyone uses.

---

Run it yourself: `python terraform_audit.py <ns>/<name>/<provider>` or
`python terraform_audit.py ./path/to/module`.
Reproduce the corpus run: `scripts/bulk_scan.py list | fetch | scan`.

*Findings are pattern matches warranting human review, not verdicts. No module in the scanned
corpus is accused of anything. Report a suspected malicious module to HashiCorp
(security@hashicorp.com) and the module's source host, not as an unverified public accusation.*
