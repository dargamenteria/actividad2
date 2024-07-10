
resource "azurerm_network_security_group" "nsg" {
  for_each            = { for k, v in var.nsg : k => v if v.enabled == true } #only enabled ones
  name                = each.key
  location            = each.value.location
  resource_group_name = azurerm_resource_group.rgs[each.value.rg].name
}


resource "azurerm_network_security_rule" "nsgr" {
  for_each = { for k, v in var.nsgr : k => v } #only enabled ones
  name     = each.key

  resource_group_name         = azurerm_resource_group.rgs[each.value.rg].name
  network_security_group_name = each.value.nsg

  priority                   = each.value.priority
  direction                  = each.value.direction
  access                     = each.value.access
  protocol                   = each.value.protocol
  source_port_range          = each.value.source_range
  destination_port_range     = each.value.destination_range
  source_address_prefix      = each.value.source_prefix
  destination_address_prefix = each.value.destination_prefix
}

resource "azurerm_subnet_network_security_group_association" "sb_nsg" {
  for_each                  = { for k, v in var.snet_nsg : k => v }
  subnet_id                 = azurerm_subnet.snets[each.value.snet].id
  network_security_group_id = azurerm_network_security_group.nsg[each.value.nsg].id
}
