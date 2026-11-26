data "http" "myip" {
  url = "https://checkip.amazonaws.com"
  request_headers = {
    Accept = "text/plain"
  }
}

data "http" "github_meta" {
  url             = "https://api.github.com/meta"
  request_headers = { Authorization = "Bearer ${var.github_token}" }
}

variable "github_token" { sensitive = true }

locals {
  my_cidr = "${chomp(data.http.myip.response_body)}/32"
}
