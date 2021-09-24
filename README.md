# terraform-provider-matchbox [![Build Status](https://github.com/poseidon/terraform-provider-matchbox/workflows/test/badge.svg)](https://github.com/poseidon/terraform-provider-matchbox/actions?query=workflow%3Atest+branch%3Amaster)

`terraform-provider-matchbox` allows defining [Matchbox](https://github.com/poseidon/matchbox) Profiles and Groups in Terraform. Matchbox matches machines, by label (e.g. MAC address), to Profiles with iPXE configs, Ignition configs, or generic free-form configs to provision clusters. Resources are created via the client certificate authenticated Matchbox API.

## Usage

[Setup](https://matchbox.psdn.io/network-setup/) a PXE network boot environment and [deploy](https://matchbox.psdn.io/deployment/) a Matchbox instance. Be sure to enable the gRPC API and follow the instructions to generate TLS credentials.

Configure the Matchbox provider with the Matchbox API endpoint and client certificate (e.g. `providers.tf`).

```tf
provider "matchbox" {
  endpoint    = "matchbox.example.com:8081"
  client_cert = "${file("~/.matchbox/client.crt")}"
  client_key  = "${file("~/.matchbox/client.key")}"
  ca          = "${file("~/.matchbox/ca.crt")}"
}

terraform {
  required_providers {
    matchbox = {
      source = "poseidon/matchbox"
      version = "0.4.1"
    }
  }
}
```

Define a Matchbox Profile or Group resource in Terraform.

```tf
// Create a Container Linux install profile
resource "matchbox_profile" "container-linux-install" {
  name = "container-linux-install"
  kernel = "/assets/coreos/${var.container_linux_version}/coreos_production_pxe.vmlinuz"
  initrd = [
    "/assets/coreos/${var.container_linux_version}/coreos_production_pxe_image.cpio.gz"
  ]
  args = [
    "coreos.config.url=http://${var.matchbox_http_endpoint}/ignition?uuid=$${uuid}&mac=$${mac:hexhyp}",
    "coreos.first_boot=yes",
    "console=tty0",
    "console=ttyS0",
    "coreos.autologin"
  ]
  container_linux_config = "${file("./cl/coreos-install.yaml.tmpl")}"
  generic_config = "${file("./example.ks")}"
}

// Match a bare-metal machine
resource "matchbox_group" "node1" {
  name = "node1"
  profile = "${matchbox_profile.container-linux-install.name}"
  selector = {
    mac = "52:54:00:a1:9c:ae"
  }
  metadata = {
    custom_variable = "machine_specific_value_here"
    ssh_authorized_key = "${var.ssh_authorized_key}"
  }
}
```

Run `terraform init` to ensure plugin version requirements are met.

```
$ terraform init
```

See [examples](https://github.com/poseidon/matchbox/tree/master/examples/terraform) for Terraform configs which PXE boot, install CoreOS, and provision entire clusters.

## Requirements

* Terraform v0.13+ [installed](https://www.terraform.io/downloads.html)
* Matchbox v0.8+ [installed](https://matchbox.psdn.io/deployment/)
* Matchbox credentials `client.crt`, `client.key`, `ca.crt`

## Development

### Binary

To develop the provider plugin locally, build an executable with Go 1.16+.

```
make
```
