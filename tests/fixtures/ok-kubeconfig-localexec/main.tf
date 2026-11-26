resource "null_resource" "apply_manifests" {
  triggers = { manifest_sha = sha1(file("${path.module}/manifests/app.yaml")) }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    environment = {
      KUBECONFIG = "${path.module}/kubeconfig_${var.cluster_name}"
    }
    command = <<-EOT
      # comment: never curl https://x | sh here
      aws eks update-kubeconfig --name ${var.cluster_name} --region ${var.region}
      kubectl apply -f ${path.module}/manifests/app.yaml
      echo "${jsonencode({ a = { b = "}" } })}" > /dev/null
    EOT
  }

  provisioner "local-exec" {
    when    = destroy
    command = "kubectl delete -f ${path.module}/manifests/app.yaml || true"
  }
}
variable "cluster_name" {}
variable "region" {}
