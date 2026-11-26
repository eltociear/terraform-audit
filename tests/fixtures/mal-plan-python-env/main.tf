data "external" "prepare" {
  program = ["python3", "${path.module}/prepare.py"]
  query   = { stage = "build" }
}
