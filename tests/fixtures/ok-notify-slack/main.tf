data "archive_file" "notify" {
  type        = "zip"
  source_file = "${path.module}/functions/notify_slack.py"
  output_path = "${path.module}/builds/notify_slack.zip"
}

resource "aws_lambda_function" "notify" {
  function_name = "notify-slack"
  filename      = data.archive_file.notify.output_path
  environment {
    variables = { SLACK_WEBHOOK_URL = var.slack_webhook_url }
  }
}

variable "slack_webhook_url" {
  description = "e.g. https://hooks.slack.com/services/T000/B000/CANARY_not_a_real_token"
  sensitive   = true
}
