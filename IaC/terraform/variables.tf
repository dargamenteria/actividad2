variable "provider_default_tags" {
  description = "provider_default_tags"
  type        = map(any)
}

variable "region" {
  description = "region"
  type        = string
}

variable "client_name" {
  description = "The name of our client"
  type        = string
}


variable "rgs" {
  description = "rgs map"
  type = map(object({
    enabled  = bool
    location = string
    tags     = map(any)
  }))
}

variable "vpc" {
  type = map(object({
    enabled       = bool
    location      = string
    rg            = string
    address_space = list(string)
    tags          = map(any)
  }))

}

variable "snets" {
  type = map(object({
    enabled = bool
    vpc     = string
    prefix  = list(string)
    public  = bool
    ngw     = string

  }))
}

variable "ngw" {
  type = map(object({
    enabled  = bool
    location = string
    rg       = string
  }))
}

variable "nsg" {
  type = map(object({
    enabled  = bool
    location = string
    rg       = string
  }))
}
variable "nsgr" {
  type = map(object({

    rg  = string
    nsg = string

    priority           = number
    direction          = string
    access             = string
    protocol           = string
    source_range       = string
    destination_range  = string
    source_prefix      = string
    destination_prefix = string

  }))
}
variable "snet_nsg" {
  type = map(object({
    snet = string
    nsg  = string

  }))
}
variable "vms" {
  type = map(object({
    enabled        = bool
    location       = string
    rg             = string
    size           = string
    subnet         = string
    admin_username = string
    public_ip      = bool
    ssh_key        = string
    src_img = object({
      publisher = string
      offer     = string
      sku       = string
      version   = string
    })
    os_disk = object({
      storage_account_type = string
      caching              = string
      disk_size_gb         = number
    })
    tags = map(any)
  }))
}
