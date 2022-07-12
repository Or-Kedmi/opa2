package policies

import input as tfplan

# --- Validate provider ---

get_basename(path) = basename{
    arr := split(path, "/")
    basename:= arr[count(arr)-1]
}

deny[reason] {
  provider_name:=get_basename(tfplan.resource_changes[_].provider_name)
  provider_name != data.provider_name
  reason := concat(" ",["Invalid provider name:", sprintf("%s", [data.provider_name])])
}
