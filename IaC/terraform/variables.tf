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
    rgs_tags = map(any)
  }))
}

variable "vpc" {
  type = map(object({
    enabled       = bool
    location      = string
    rgs           = string
    address_space = list(string)
    rgs_tags      = map(any)


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
    rgs      = string
  }))
}


