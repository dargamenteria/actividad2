
resource "azurerm_network_security_group" "nsg" {
  for_each            = { for k, v in var.nsg : k => v if v.enabled == true } #only enabled ones
  name                = each.key
  location            = each.value.location
  resource_group_name = azurerm_resource_group.rgs[each.value.rg].name
  tags                = merge(each.value.tags, var.provider_default_tags)
}


resource "azurerm_network_security_rule" "nsgr" {
  # nsrg is a list
  # convert it to k => V
  # The key is combination of rg,nsg, and sha1 of several values
  for_each = { for rule in var.nsgr : join("-", [rule.rg, rule.nsg, sha1("${rule.rg}${rule.sr}${rule.dr}${rule.sp}${rule.dp}")])
  => rule }

  name = each.key

  resource_group_name         = azurerm_resource_group.rgs[each.value.rg].name
  network_security_group_name = each.value.nsg

  priority               = each.value.priority
  direction              = each.value.direction
  access                 = each.value.access
  protocol               = each.value.protocol
  source_port_range      = each.value.sr
  destination_port_range = each.value.dr
  #Need a list fof sap an dap 
  # if != * 
  #   if have dots 
  #     mean  we have a string with ips so convert the string onto list of ips
  #   else
  #     go to the local ip_map and get its contents
  # else
  #   return *
  source_address_prefixes      = [each.value.sr] != "*" ? strcontains(each.value.sp, ".") ? tolist(split(", ", each.value.sp)) : ["${local.ip_map[each.value.sp]}/32"] : ["*"]
  destination_address_prefixes = [each.value.dr] != "*" ? strcontains(each.value.dp, ".") ? tolist(split(", ", each.value.dp)) : ["${local.ip_map[each.value.dp]}/32"] : ["*"]
}

resource "azurerm_subnet_network_security_group_association" "sb_nsg" {
  for_each                  = { for k, v in var.snet_nsg : k => v }
  subnet_id                 = azurerm_subnet.snets[each.value.snet].id
  network_security_group_id = azurerm_network_security_group.nsg[each.value.nsg].id
}
