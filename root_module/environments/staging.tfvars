environment        = "staging"
region             = "eu-west-1"
allowed_account_id = "REPLACE-ME-12-digit-staging-account-id"
bucket_name        = "REPLACE-ME-staging-dlp-data"
alert_emails       = ["REPLACE-ME@example.com"]
monthly_limit_usd  = 100

# Roles that may read Sensitive objects / release false positives. Leave empty until one exists.
break_glass_role_arns = []

# Deny reads until Macie has scanned an object (see README, "Fail-closed mode").
fail_closed = false

# Set true on a later deploy, once the CostCenter tag shows up in billing (up to 24h).
activate_cost_allocation_tag = false
