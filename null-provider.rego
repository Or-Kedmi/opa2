package policy

import input as tfplan

# --- Validate provider ---

get_basename(path) = basename{
    arr := split(path, "/")
    basename:= arr[count(arr)-1]
}

is_allowed_provider(provider_name) {
    {"null"}[provider_name]
}

deny[reason] {
  provider_name:=get_basename(tfplan.resource_changes[_].provider_name)
  not is_allowed_provider(provider_name)
  reason := concat(" ",["Invalid provider name:", sprintf("%s", [provider_name])])
}
