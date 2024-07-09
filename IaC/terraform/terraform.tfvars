region      = "West Europe"
client_name = "unir"

provider_default_tags = {
  environment = "unir"
  terraform   = "true"
}

rgs = {

  unir = {
    enabled  = true,
    location = "West Europe"
    rgs_tags = {
    }
  }
}

#vpc = {
#  location = "West Europe"
#  name     = "unir-vpc"
#
#  address_space = ["10.0.0.0/16"]
#
#  subnets      = ["10.0.1.0/24", "10.0.2.0/24"]
#  subnet_names = ["unit-snet1", "unir-snet2"]
#}

vpc = {
  "unir_vpc" = {
    enabled       = true
    location      = "West Europe"
    rgs           = "unir"
    address_space = ["10.0.0.0/16"]
    rgs_tags = {
    }
  }
}

ngw = {
  "unir_ngw" = {
    enabled  = true
    location = "West Europe"
    rgs      = "unir"
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
    enabled = true
    vpc     = "unir_vpc"
    prefix  = ["1.0.1.0/24"]
    public  = false
    ngw     = ""
  }
}
