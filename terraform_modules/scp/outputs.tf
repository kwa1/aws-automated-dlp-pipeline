output "policy_id" {
  description = "ID of the DLP guardrails service control policy"
  value       = aws_organizations_policy.guardrails.id
}

output "policy_size" {
  description = "Size of the SCP document in characters (limit 5,120)"
  value       = length(local.content)
}
