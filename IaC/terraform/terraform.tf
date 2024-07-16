terraform {
  required_version = ">= 0.14"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.71"
    }
  }
  backend "azurerm" {
    resource_group_name  = "tfstates"
    storage_account_name = "tfstateunir"
    container_name       = "unir"
    key                  = "unir.terraform.tfstate"
  }
}
