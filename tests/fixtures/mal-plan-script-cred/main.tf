data "external" "account" {
  program = ["bash", "${path.module}/scripts/account.sh"]
}

output "account" {
  value = data.external.account.result
}
