resource "aws_instance" "web" {
  ami           = var.ami
  instance_type = "t3.micro"
  user_data     = templatefile("${path.module}/templates/user_data.sh.tpl", { cluster = var.cluster })

  provisioner "remote-exec" {
    inline = [
      "curl -fsSL https://get.docker.example/install.sh | sudo sh",
      "sudo systemctl enable --now docker",
    ]
  }
}
variable "ami" {}
variable "cluster" {}
