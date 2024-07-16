resource "azurerm_container_registry" "acr" {
  for_each = { for k, v in var.acr : k => v if v.enabled == true } #only enabled ones
  name     = "${each.key}unir"
  location = each.value.location

  resource_group_name = azurerm_resource_group.rgs[each.value.rg].name
  sku                 = each.value.sku
  admin_enabled       = true
  tags                = merge(each.value.tags, var.provider_default_tags)
}
