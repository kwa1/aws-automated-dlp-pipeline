# The remediation Lambda publishes findings to the account's default Security
# Hub product, so Security Hub must be enabled. Default standards are left off
# to avoid unplanned per-check charges; enable them deliberately later.
resource "aws_securityhub_account" "this" {
  enable_default_standards  = false
  auto_enable_controls      = false
  control_finding_generator = "SECURITY_CONTROL"
}
