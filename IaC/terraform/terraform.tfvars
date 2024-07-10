region      = "North Europe"
client_name = "unir-arga2"

provider_default_tags = {
  environment = "unir"
  terraform   = "true"
}

rgs = {

  unir-arga2 = {
    enabled  = true,
    location = "North Europe"
    tags = {
    }
  }
}



vpc = {
  "unir_vpc" = {
    enabled       = true
    location      = "North Europe"
    rg            = "unir-arga2"
    address_space = ["10.0.0.0/16"]
    tags = {
    }
  }
}

ngw = {
  "unir_ngw" = {
    enabled  = true
    location = "North Europe"
    rg       = "unir-arga2"
  }
}

snets = {
  "pub_snet_a" = {
    enabled = true
    vpc     = "unir_vpc"
    prefix  = ["10.0.0.0/24"]
    public  = true
    ngw     = "unir_vpc"
  }
  "prv_snet_a" = {
    enabled = false
    vpc     = "unir_vpc"
    prefix  = ["1.0.1.0/24"]
    public  = false
    ngw     = ""
  }
}

nsg = {
  "public" = {
    enabled  = true
    location = "North Europe"
    rg       = "unir-arga2"
  }
}

nsgr = {
  "allow_ssh_public" = {
    priority           = 100
    direction          = "Inbound"
    access             = "Allow"
    protocol           = "Tcp"
    source_range       = "*"
    destination_range  = "22"
    source_prefix      = "*"
    destination_prefix = "*"
    rg                 = "unir-arga2"
    nsg                = "public"
  }
  "allow_http_public" = {
    priority           = 101
    direction          = "Inbound"
    access             = "Allow"
    protocol           = "Tcp"
    source_range       = "*"
    destination_range  = "80"
    source_prefix      = "*"
    destination_prefix = "*"
    rg                 = "unir-arga2"
    nsg                = "public"
  }
}

snet_nsg = {
  "snet_pub_snet_a_nsg_public" = {
    snet = "pub_snet_a"
    nsg  = "public"
  }
}

vms = {
  "webserver" = {
    enabled        = true
    location       = "North Europe"
    rg             = "unir-arga2"
    size           = "Standard_D2s_v3"
    subnet         = "pub_snet_a"
    admin_username = "ubuntu"
    public_ip      = true
    ssh_key        = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDj/qvzCFBoF7piKZzY7faURI4IeZowQGWhIzIkruxqmYz2CQOxjrr02dNM68ndJb/0nHv0aVApUzSsVPCjpq9FcVhysjtmKnPedDLpsQL2gCKoJJmlGAVNt/xLsV57dxma1/5Vf3oLjgKavQUG/PDho2z62/hg0U+MUoegcjG7STKVuidOWGE3mNsKIksWs1wI6y20ONO4ueO1pKWBBSZbCxK/lRo+gf6jiEVqmwxvOSv453H4ta4PN7iRpInwDQU1Dxz+tCewPLID8d5Ewgao4a9oL04H0io8ESSSnnxyVaNbbG/pEOhN1MER81e2IS2MVXu7bodPIAPIjOMUrN8/ dani@draco"
    src_img = {
      publisher = "canonical"
      offer     = "0001-com-ubuntu-server-jammy"
      sku       = "22_04-lts-gen2"
      version   = "latest"
    }
    os_disk = {
      storage_account_type = "Standard_LRS"
      caching              = "ReadWrite"
      disk_size_gb         = 30
    }
    tags = {}
  }
}
