# confium-terraform-provider

Terraform provider for deploying Confium infrastructure to Kubernetes.

## Usage

```hcl
terraform {
  required_providers {
    confium = {
      source = "confium/confium"
    }
  }
}

provider "confium" {}

resource "confium_signerd" "main" {
  replicas = 3
  threshold = 2
}
```

## Documentation

- [Confium documentation](https://www.confium.org/)
- [Terraform registry](https://registry.terraform.io/providers/confium/confium)

## License

BSD-2-Clause.
