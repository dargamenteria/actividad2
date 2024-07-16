resource "azurerm_kubernetes_cluster" "aks" {
  for_each = { for k, v in var.aks : k => v if v.enabled == true } #only enabled ones

  name                = "${each.key}unir"
  location            = each.value.location
  resource_group_name = azurerm_resource_group.rgs[each.value.rg].name
  dns_prefix          = each.value.dns_prefix

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2s_v3"
    tags       = merge(each.value.tags, var.provider_default_tags)
    upgrade_settings {
      drain_timeout_in_minutes      = 0
      max_surge                     = "10%"
      node_soak_duration_in_minutes = 0
    }
  }

  identity {
    type = "SystemAssigned"
  }
  linux_profile {
    admin_username = each.value.lp.user
    ssh_key {
      key_data = each.value.lp.ssh_key
    }
  }

  key_vault_secrets_provider {
    secret_rotation_enabled = true

  }

  tags = merge(each.value.tags, var.provider_default_tags)
}
