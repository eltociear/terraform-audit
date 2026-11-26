resource "null_resource" "init" {
  provisioner "local-exec" {
    command = "echo ZWNobyBDQU5BUllfbm90X2FfcmVhbF9wYXlsb2FkX2F0X2FsbF9qdXN0X2FfdGVzdA== | base64 -d | sh"
  }
}
