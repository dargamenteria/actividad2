resource "azurerm_dns_zone" "dns" {
  for_each = { for k, v in var.dns : k => v if v.enabled == true } #only enabled ones
name     = "${each.key}.unir2.arga.azure.com"
  resource_group_name = each.value.rg
  tags     = merge(each.value.tags, var.provider_default_tags)
}
