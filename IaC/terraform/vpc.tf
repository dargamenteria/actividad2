#Creating a NAT Gateway in the specified location.
resource "azurerm_nat_gateway" "ngw" {
  for_each            = { for k, v in var.ngw : k => v if v.enabled == true }
  location            = each.value.location
  name                = each.key
  resource_group_name = azurerm_resource_group.rgs[each.value.rgs].name
}

resource "azurerm_public_ip" "ngw-ip" {
  for_each            = { for k, v in var.ngw : k => v if v.enabled == true }
  location            = each.value.location
  name                = "${each.key}-ip"
  resource_group_name = azurerm_resource_group.rgs[each.value.rgs].name
  allocation_method   = "Static"
  sku                 = "Standard"
}



resource "azurerm_virtual_network" "vpc" {
  for_each            = { for k, v in var.vpc : k => v if v.enabled == true }
  name                = each.key
  resource_group_name = azurerm_resource_group.rgs[each.value.rgs].name
  address_space       = each.value.address_space
  location            = each.value.location

  tags = merge(each.value.rgs_tags, var.provider_default_tags)

}

resource "azurerm_subnet" "snets" {
  for_each                        = { for k, v in var.snets : k => v if v.enabled == true }
  name                            = each.key
  resource_group_name             = var.vpc[each.value.vpc].rgs
  virtual_network_name            = each.value.vpc
  address_prefixes                = each.value.prefix
  default_outbound_access_enabled = each.value.public
}

