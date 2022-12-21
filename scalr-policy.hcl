version = "v1"

policy "enforce_aws_resource" {
  enabled           = true
  #enforcement_level = "hard-mandatory"
  enforcement_level = "advisory"
}

policy "enforce_tags" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}
