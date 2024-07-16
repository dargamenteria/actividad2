data "template_file" "deployer_vars" {
  template = file("./resources/templates/deployer_vars.tpl")
  vars = {
    admin_password = azurerm_container_registry.acr["acr"].admin_password
    admin_username = azurerm_container_registry.acr["acr"].admin_username
    dest_repo      = azurerm_container_registry.acr["acr"].login_server
  }
  depends_on = [
    azurerm_container_registry.acr["acr"]
  ]
}

resource "local_file" "deployer_vars" {
  content  = data.template_file.deployer_vars.rendered
  filename = "../ansible/inventories/local/group_vars/local/main.yml"

  provisioner "local-exec" {
    working_dir = "../ansible"
    command     = "ansible-playbook -v -i inventories/local/hosts.yml -u dani -b  registry.yml"
  }

  depends_on = [
    azurerm_container_registry.acr["acr"]
  ]

}



data "template_file" "remote_vars" {
  template = file("./resources/templates/remote_vars.tpl")
  vars = {
    admin_password = azurerm_container_registry.acr["acr"].admin_password
    admin_username = azurerm_container_registry.acr["acr"].admin_username
    dest_repo      = azurerm_container_registry.acr["acr"].login_server
  }
}


resource "local_file" "remote_vars" {
  content  = data.template_file.remote_vars.rendered
  filename = "../ansible/inventories/azure/group_vars/azure/main.yml"

  depends_on = [
    local_file.deployer_vars,
    azurerm_linux_virtual_machine.vms["webserver"],
    azurerm_public_ip.pub_ip["webserver"]

  ]
}


data "template_file" "remote_inventory" {
  #"azurerm_linux_virtual_machine" "vms"

  #azurerm_public_ip.pub_ip["webserver"]
  template = file("./resources/templates/remote_inventory.tpl")
  vars = {
    tfhost = azurerm_public_ip.pub_ip["webserver"].ip_address
  }
  depends_on = [
    azurerm_linux_virtual_machine.vms["webserver"],
    azurerm_public_ip.pub_ip["webserver"]
  ]

}

resource "local_file" "remote_inventory" {
  content  = data.template_file.remote_inventory.rendered
  filename = "../ansible/inventories/azure/hosts.yml"

  provisioner "local-exec" {
    working_dir = "../ansible"
    command     = "ansible-playbook -v -i inventories/azure/hosts.yml -u ubuntu  tfnode.yml"
  }
  depends_on = [
    local_file.deployer_vars,
    azurerm_linux_virtual_machine.vms["webserver"],
    azurerm_public_ip.pub_ip["webserver"]

  ]

}

resource "local_file" "k8s_config" {
  content  = azurerm_kubernetes_cluster.aks["aks"].kube_config_raw
  filename = "../ansible/roles/aks/files/config.yml"

  provisioner "local-exec" {
    working_dir = "../ansible"
    command     = "ansible-playbook -v -i inventories/local/hosts.yml -u dani aks.yml"
  }
  depends_on = [
    azurerm_kubernetes_cluster.aks["aks"]
  ]
}






