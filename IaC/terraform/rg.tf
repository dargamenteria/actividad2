resource "azurerm_resource_group" "rgs" {
  for_each    = { for k, v in var.rgs : k => v if v.enabled == true } #only enabled ones
  name        = each.key
  location    = each.value.location
  tags        = merge (each.value.rgs_tags, var.provider_default_tags)
}
