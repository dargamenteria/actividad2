#!/bin/bash

RESOURCE_GROUP_NAME=tfstates
STORAGE_ACCOUNT_NAME=tfstate-unir
CONTAINER_NAME=unir

az group create --name $RESOURCE_GROUP_NAME --location madrid
az storage account create --resource-group $RESOURCE_GROUP_NAME --name $STORAGE_ACCOUNT_NAME --sku Standard_LRS --encryption-services blob
az storage container create --name $CONTAINER_NAME --account-name $STORAGE_ACCOUNT_NAME

