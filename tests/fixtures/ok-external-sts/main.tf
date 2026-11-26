data "external" "thumbprint" {
  program = ["bash", "${path.module}/scripts/thumbprint.sh", var.region]
}
variable "region" {}
