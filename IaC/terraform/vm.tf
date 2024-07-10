resource "azurerm_public_ip" "pub_ip" {
  for_each            = { for k, v in var.vms : k => v if v.enabled == true && v.public_ip == true }
  name                = "${each.key}-public-ip"
  location            = each.value.location
  resource_group_name = azurerm_resource_group.rgs[each.value.rg].name
  allocation_method   = "Dynamic"
}

resource "azurerm_network_interface" "wms_ani" {
  for_each = { for k, v in var.vms : k => v if v.enabled == true } #only enabled ones

  name                = "${each.key}-ani"
  resource_group_name = azurerm_resource_group.rgs[each.value.rg].name
  location            = each.value.location

  ip_configuration {
    name                          = "${each.key}-ani-config"
    subnet_id                     = azurerm_subnet.snets[each.value.subnet].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = each.value.public_ip == true ? azurerm_public_ip.pub_ip[each.key].id : null
  }
}


resource "azurerm_linux_virtual_machine" "vms" {
  for_each = { for k, v in var.vms : k => v if v.enabled == true } #only enabled ones
  name     = each.key
  location = each.value.location

  resource_group_name   = azurerm_resource_group.rgs[each.value.rg].name
  network_interface_ids = [azurerm_network_interface.wms_ani[each.key].id]
  size                  = each.value.size
  computer_name         = each.key
  admin_username        = each.value.admin_username
  #disable_password_authentication = false

  custom_data = filebase64("./resources/scripts/cloud-init.yml")

  admin_ssh_key {
    username   = each.value.admin_username
    public_key = each.value.ssh_key
  }

  source_image_reference {
    publisher = each.value.src_img.publisher
    offer     = each.value.src_img.offer
    sku       = each.value.src_img.sku
    version   = each.value.src_img.version
  }

  os_disk {
    name                 = "${each.key}-osdisk"
    storage_account_type = each.value.os_disk.storage_account_type
    caching              = each.value.os_disk.caching
    disk_size_gb         = each.value.os_disk.disk_size_gb
  }
  tags = merge(each.value.tags, var.provider_default_tags)

}
