# see https://github.com/hashicorp/terraform
terraform {
  required_version = "1.2.8"
  required_providers {
    # see https://github.com/hashicorp/terraform-provider-random
    # see https://registry.terraform.io/providers/hashicorp/random
    random = {
      source  = "hashicorp/random"
      version = "3.4.2"
    }
    # see https://github.com/hashicorp/terraform-provider-time
    # see https://registry.terraform.io/providers/hashicorp/time
    time = {
      source  = "hashicorp/time"
      version = "0.8.0"
    }
    # see https://github.com/terraform-providers/terraform-provider-azurerm
    # see https://registry.terraform.io/providers/hashicorp/azurerm
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "3.21.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# NB you can test the relative speed from you browser to a location using https://azurespeedtest.azurewebsites.net/
# get the available locations with: az account list-locations --output table
variable "location" {
  default = "northeurope"
}

# NB this name must be unique within the Azure subscription.
#    all the other names must be unique within this resource group.
variable "resource_group_name" {
  default = "rgl-terraform-azure-dns-lego-lets-encrypt"
}

variable "zone_name" {
  default = "dev.example.com"
}

data "azuread_client_config" "current" {
}

data "azurerm_client_config" "current" {
}

output "client_id" {
  value = azuread_service_principal.lego.application_id
}

output "client_secret" {
  value = azuread_application_password.lego.value
  sensitive = true
}

output "resource_group" {
  value = azurerm_resource_group.example.name
}

output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
  sensitive = true
}

output "tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
  sensitive = true
}

output "name_servers" {
  value = azurerm_dns_zone.le.name_servers
}

# see https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group
resource "azurerm_resource_group" "example" {
  name = var.resource_group_name # NB this name must be unique within the Azure subscription.
  location = var.location
}

# see https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/dns_zone
resource "azurerm_dns_zone" "le" {
  resource_group_name = azurerm_resource_group.example.name
  name = var.zone_name
}

# see https://registry.terraform.io/providers/hashicorp/azuread/latest/docs/resources/application
resource "azuread_application" "lego" {
  display_name = "lego"
  owners = [data.azuread_client_config.current.object_id]
}

# see https://registry.terraform.io/providers/hashicorp/time/latest/docs/resources/rotating
resource "time_rotating" "lego" {
  rotation_days = 7
}

# see https://registry.terraform.io/providers/hashicorp/azuread/latest/docs/resources/application_password
resource "azuread_application_password" "lego" {
  application_object_id = azuread_application.lego.object_id
  rotate_when_changed = {
    rotation = time_rotating.lego.id
  }
}

# see https://registry.terraform.io/providers/hashicorp/azuread/latest/docs/resources/service_principal
resource "azuread_service_principal" "lego" {
  application_id = azuread_application.lego.application_id
  owners = [data.azuread_client_config.current.object_id]
  app_role_assignment_required = false
}

# see https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment
resource "azurerm_role_assignment" "lego" {
  scope = azurerm_dns_zone.le.id
  principal_id = azuread_service_principal.lego.id
  role_definition_name = "DNS Zone Contributor"
}
