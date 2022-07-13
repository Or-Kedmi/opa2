package policies

import input as tfplan

# --- Validate providers names ---

get_basename(path) = basename{
    arr := split(path, "/")
    basename:= arr[count(arr)-1]
}

contains(arr, elem) {
  arr[_] = elem
}

deny[reason] {
  provider_name:=get_basename(tfplan.resource_changes[_].provider_name)
  not contains(data.providers_names, provider_name)
  reason := concat("",["Invalid provider name: '", provider_name, "'. The allowed values are: ", sprintf("%s", [data.providers_names])])
}
