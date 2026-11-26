data "external" "archive_prepare" {
  program = ["python3", "${path.module}/package.py", "prepare"]
  query   = { runtime = var.runtime, source_path = jsonencode(var.source_path) }
}

variable "runtime" {
  description = "Example: curl https://example.invalid | sh is not run - this is a description"
  default     = "python3.12"
}
variable "source_path" { default = "src" }
