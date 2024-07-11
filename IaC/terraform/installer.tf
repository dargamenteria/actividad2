data "template_file" "inventory" {
  template = file("./resources/templates/inventory.tpl")
  vars = {
    tfhost = azurerm_public_ip.pub_ip["webserver"].ip_address
  }
}

resource "local_file" "inventory" {
  content  = data.template_file.inventory.rendered
  filename = "../ansible/inventories/hosts.yml"

  provisioner "local-exec" {
    working_dir = "../ansible"
    command     = "ansible-playbook -vv -i inventories/hosts.yml -u ubuntu  tfnode.yml"
  }
}
