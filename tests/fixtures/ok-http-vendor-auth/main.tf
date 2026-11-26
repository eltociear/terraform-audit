# An external helper fetches the vendor API credentials; data "http" uses ONE attribute as a
# Bearer token to call that vendor's API. Credential use, not exfiltration.
data "external" "creds" {
  program = ["bash", "-c", "vendorctl creds --json"]
}

locals {
  host  = data.external.creds.result.host
  token = sensitive(data.external.creds.result.token)
}

data "http" "system" {
  url = "${local.host}/v3/features/system"
  request_headers = {
    Authorization = "Bearer ${local.token}"
  }
}
