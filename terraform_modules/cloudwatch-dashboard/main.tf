resource "aws_cloudwatch_dashboard" "dlp_costs" {
  dashboard_name = "Security-DLP-Costs"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "text"
        x    = 0
        y    = 0
        width  = 24
        height = 3
        properties = {
          markdown = "# 🔐 Security DLP Cost Dashboard\nTracks Macie-driven DLP spend and anomalies"
        }
      },
      {
        type = "metric"
        x    = 0
        y    = 3
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/Billing", "EstimatedCharges", "ServiceName", "Amazon Macie", { "stat": "Maximum" }]
          ]
          period = 86400
          region = "us-east-1"
          title  = "Amazon Macie Estimated Charges"
        }
      }
    ]
  })
}
