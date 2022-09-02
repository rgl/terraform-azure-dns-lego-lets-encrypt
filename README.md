# About

[![Lint](https://github.com/rgl/terraform-azure-dns-lego-lets-encrypt/actions/workflows/lint.yml/badge.svg)](https://github.com/rgl/terraform-azure-dns-lego-lets-encrypt/actions/workflows/lint.yml)

This create an [Let's Encrypt](https://letsencrypt.org) issued certificate using the [ACME DNS-01 challenge](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge) from a [Azure DNS Zone](https://azure.microsoft.com/en-us/services/dns/) using the [Terraform azuread](https://registry.terraform.io/providers/hashicorp/azuread) and [Terraform azurerm](https://registry.terraform.io/providers/hashicorp/azurerm) providers.

This will:

* Create an Azure DNS Zone.
* Create an Azure Application and Service Principal with permissions to modify the DNS Zone.
* Use [`lego`](https://github.com/go-acme/lego) to create a [Let's Encrypt](https://letsencrypt.org) issued certificate using the [ACME DNS challenge](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge).

# Table Of Contents

* [Usage (Ubuntu)](#usage-ubuntu)
* [Usage (Windows)](#usage-windows)

# Usage (Ubuntu)

Install dependencies:

* `az` (see [my ubuntu ansible azure-client role](https://github.com/rgl/my-ubuntu-ansible-playbooks/tree/main/roles/azure-client))
* `terraform` (see [my ubuntu ansible terraform role](https://github.com/rgl/my-ubuntu-ansible-playbooks/tree/main/roles/terraform))

Install more dependencies:

```bash
sudo apt-get install -y openssl
sudo apt-get install -y jq
npm ci
```

Login into Azure:

```bash
az login
```

List the subscriptions and select the currect one.

```bash
az account list --all
az account show
az account set --subscription <YOUR-SUBSCRIPTION-ID>
```

Provision the example infrastructure:

```bash
export CHECKPOINT_DISABLE='1'
export TF_LOG='TRACE'
export TF_LOG_PATH='terraform.log'
# set the region.
export TF_VAR_location='northeurope'
# set the dns zone to create.
export TF_VAR_dns_zone='dev.example.com'
# initialize.
terraform init
# provision.
terraform plan -out=tfplan
terraform apply tfplan
```

Show the DNS Zone nameservers:

```powershell
terraform output -json name_servers
```

Using your parent domain DNS Registrar or DNS Hosting provider, delegate the
`$env:TF_VAR_dns_zone` DNS Zone to the returned nameservers. For example, at
the parent domain DNS Zone, add:

```
dev NS ns1-01.azure-dns.com.
dev NS ns2-01.azure-dns.net.
dev NS ns3-01.azure-dns.org.
dev NS ns4-01.azure-dns.info.
```

Verify the delegation:

```bash
nameserver="$(terraform output -json name_servers | jq -r '.[0]')"
dig ns $TF_VAR_dns_zone "@$nameserver"
```

Use `lego` to generate a certificate:

```bash
# see https://github.com/go-acme/lego
# see https://go-acme.github.io/lego/dns/azure/
url='https://github.com/go-acme/lego/releases/download/v4.8.0/lego_v4.8.0_linux_amd64.tar.gz'
path="tmp/$(basename "$url")"
mkdir -p tmp
wget -O "$path" "$url"
tar xf "$path" -C tmp
lego="$PWD/tmp/lego"
# NB these values could also come from files by appending _FILE to the
#    AZURE_* environment variable names.
export AZURE_CLIENT_ID="$(terraform output -raw client_id)"
export AZURE_CLIENT_SECRET="$(terraform output -raw client_secret)"
export AZURE_RESOURCE_GROUP="$(terraform output -raw resource_group)"
export AZURE_SUBSCRIPTION_ID="$(terraform output -raw subscription_id)"
export AZURE_TENANT_ID="$(terraform output -raw tenant_id)"
export AZURE_ZONE_NAME="$TF_VAR_dns_zone"
domain="test.$AZURE_ZONE_NAME"
email="test@$AZURE_ZONE_NAME"
"$lego" \
  --path tmp/.lego \
  --accept-tos \
  --email "$email" \
  --domains "$domain" \
  --dns azure \
  run
```

You should see something alike:

```
[INFO] [test.dev.example.com] acme: Obtaining bundled SAN certificate
[INFO] [test.dev.example.com] AuthURL: https://acme-v02.api.letsencrypt.org/acme/authz-v3/148990933847
[INFO] [test.dev.example.com] acme: Could not find solver for: tls-alpn-01
[INFO] [test.dev.example.com] acme: Could not find solver for: http-01
[INFO] [test.dev.example.com] acme: use dns-01 solver
[INFO] [test.dev.example.com] acme: Preparing to solve DNS-01
[INFO] [test.dev.example.com] acme: Trying to solve DNS-01
[INFO] [test.dev.example.com] acme: Checking DNS record propagation using [google-public-dns-a.google.com:53 google-public-dns-b.google.com:53]
[INFO] Wait for propagation [timeout: 2m0s, interval: 2s]
[INFO] [test.dev.example.com] The server validated our request
[INFO] [test.dev.example.com] acme: Cleaning DNS-01 challenge
[INFO] [test.dev.example.com] acme: Validations succeeded; requesting certificates
[INFO] [test.dev.example.com] Server responded with a certificate.
```

The certificate and related files should be in `tmp/.lego/certificates` as
the following PEM encoded files:

| Filename                        | Description                        |
|---------------------------------|------------------------------------|
| test.dev.example.com.crt        | certificate and intermediate chain |
| test.dev.example.com.issuer.crt | root CA certificate                |
| test.dev.example.com.key        | private key                        |

Inspect the certificate:

```bash
openssl storeutl -noout -text -certs -in "tmp/.lego/certificates/$domain.crt"
```

You should see something alike:

```
0: Certificate
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            03:a0:a5:e6:07:0d:3b:a0:8f:52:ba:1a:f1:49:e0:65:92:db
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Let's Encrypt, CN=R3
        Validity
            Not Before: Sep  2 16:41:47 2022 GMT
            Not After : Dec  1 16:41:46 2022 GMT
        Subject: CN=test.dev.example.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:19:2f:f5:07:87:a6:b8:fe:b0:48:e7:6d:52:10:
                    b8:c7:64:69:4b:9a:38:48:66:38:92:7d:4c:5d:ba:
                    b1:cf:3c:1d:76:bf:e0:26:5e:bf:ec:1a:a7:45:4b:
                    09:89:d8:ec:f6:8c:68:71:ad:9a:36:0c:f3:f8:72:
                    62:70:67:86:21
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                97:46:7E:6F:E1:1F:D5:D6:2D:FF:86:4D:8E:E0:4F:9E:79:87:6D:5B
            X509v3 Authority Key Identifier:
                14:2E:B3:17:B7:58:56:CB:AE:50:09:40:E6:1F:AF:9D:8B:14:C2:C6
            Authority Information Access:
                OCSP - URI:http://r3.o.lencr.org
                CA Issuers - URI:http://r3.i.lencr.org/
            X509v3 Subject Alternative Name:
                DNS:test.dev.example.com
            X509v3 Certificate Policies:
                Policy: 2.23.140.1.2.1
                Policy: 1.3.6.1.4.1.44947.1.1.1
                  CPS: http://cps.letsencrypt.org
            CT Precertificate SCTs:
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : 41:C8:CA:B1:DF:22:46:4A:10:C6:A1:3A:09:42:87:5E:
                                4E:31:8B:1B:03:EB:EB:4B:C7:68:F0:90:62:96:06:F6
                    Timestamp : Sep  2 17:41:47.931 2022 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:44:02:20:18:71:FA:73:1C:39:05:B5:F6:3D:4C:D8:
                                00:6F:79:76:A4:4D:43:24:44:87:94:E5:F6:C8:61:AC:
                                AA:80:52:2D:02:20:0E:2F:DF:EA:AA:95:B1:F3:F4:C0:
                                4B:47:6F:A3:5E:36:EC:18:90:14:F9:1E:A3:8B:6A:D1:
                                12:2B:5D:F5:C7:33
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : 46:A5:55:EB:75:FA:91:20:30:B5:A2:89:69:F4:F3:7D:
                                11:2C:41:74:BE:FD:49:B8:85:AB:F2:FC:70:FE:6D:47
                    Timestamp : Sep  2 17:41:47.946 2022 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:44:02:20:7D:97:F0:E6:05:D3:B9:78:AF:B3:7D:98:
                                38:CD:D2:65:51:58:6B:8A:94:14:8C:EB:E9:1F:70:D3:
                                6F:08:30:52:02:20:25:7C:65:F6:86:E9:C8:65:F4:5A:
                                CD:91:9D:18:44:53:EA:C6:25:F3:0F:67:05:B8:D8:D8:
                                0E:B8:6E:C5:99:88
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        4e:3a:9c:23:fa:26:2b:df:0e:06:9a:5c:af:eb:d2:cc:37:16:
        51:0c:14:e8:7f:2a:fc:27:32:53:87:59:0a:e7:d3:47:25:3f:
        dc:e8:32:be:11:92:45:72:8c:95:eb:36:f5:91:01:fe:d5:7b:
        c1:1a:20:e6:5c:2c:37:c4:d4:9d:11:da:ba:4c:66:38:8c:d6:
        f9:e7:4f:03:d4:b0:7b:20:15:95:d4:da:e4:50:01:f1:e9:e7:
        8f:52:0e:fd:8b:08:53:2c:19:cf:be:22:cc:fb:48:69:4a:ef:
        2d:7a:33:42:ff:5b:1f:f7:5a:92:6e:3c:e9:52:d8:2a:c7:a0:
        96:01:2c:c9:c1:e6:9e:10:bd:26:ff:00:17:67:5e:4f:32:02:
        68:fe:81:00:b9:89:6f:de:c8:9c:74:c4:19:08:2c:f9:63:98:
        67:88:91:f4:ff:fe:62:fe:1f:a6:2f:e7:40:13:cc:9c:50:c1:
        d2:67:a2:8e:4e:49:e8:9e:24:74:06:18:ba:6f:1b:2b:30:7d:
        f9:1c:7c:3a:29:73:cb:ea:d1:2b:ed:e5:94:3d:3d:f8:0e:1a:
        87:15:cf:2c:73:37:59:64:6f:97:34:55:cd:3b:25:96:30:d0:
        28:84:bb:0a:54:cd:d0:10:3c:42:4e:a1:d8:27:29:89:64:f8:
        54:f8:fe:01
1: Certificate
Certificate:
    ...
```

Destroy everything:

```bash
terraform destroy
```

# Usage (Windows)

Install the dependencies:

```powershell
choco install -y azure-cli --version 2.39.0
choco install -y terraform --version 1.2.8
choco install -y tflint --version 0.35.0
choco install -y jq --version 1.6
choco install -y bind-toolsonly --version 9.16.28
choco install -y openssl.light --version 3.0.5
Import-Module "$env:ChocolateyInstall\helpers\chocolateyInstaller.psm1"
Update-SessionEnvironment
```

Login into Azure:

```powershell
az login
```

List the subscriptions and select the correct one.

```powershell
az account list --all
az account show
az account set --subscription <YOUR-SUBSCRIPTION-ID>
```

Provision the example infrastructure:

```powershell
$env:CHECKPOINT_DISABLE = '1'
$env:TF_LOG = 'TRACE'
$env:TF_LOG_PATH = 'terraform.log'
# set the region.
$env:TF_VAR_location = 'northeurope'
# set the dns zone to create.
$env:TF_VAR_dns_zone = 'dev.example.com'
# lint the source code.
tflint --init
tflint --loglevel trace
# initialize terraform.
terraform init
# provision.
terraform plan -out=tfplan
terraform apply tfplan
```

Show the DNS Zone nameservers:

```powershell
terraform output -json name_servers
```

Using your parent domain DNS Registrar or DNS Hosting provider, delegate the
`$env:TF_VAR_dns_zone` DNS Zone to the returned nameservers. For example, at
the parent domain DNS Zone, add:

```
dev NS ns1-01.azure-dns.com.
dev NS ns2-01.azure-dns.net.
dev NS ns3-01.azure-dns.org.
dev NS ns4-01.azure-dns.info.
```

Verify the delegation:

```powershell
$nameserver = terraform output -json name_servers | ConvertFrom-Json | Select-Object -First 1
dig ns $env:TF_VAR_dns_zone "@$nameserver"
```

Use `lego` to generate a certificate:

```powershell
# see https://github.com/go-acme/lego
# see https://go-acme.github.io/lego/dns/azure/
$url = 'https://github.com/go-acme/lego/releases/download/v4.8.0/lego_v4.8.0_windows_amd64.zip'
$path = "tmp/$(Split-Path -Leaf $url)"
mkdir -Force tmp | Out-Null
(New-Object Net.WebClient).DownloadFile($url, $path)
Expand-Archive $path tmp
$lego = Resolve-Path tmp/lego.exe
# NB these values could also come from files by appending _FILE to the
#    AZURE_* environment variable names.
$env:AZURE_CLIENT_ID        = terraform output -raw client_id
$env:AZURE_CLIENT_SECRET    = terraform output -raw client_secret
$env:AZURE_RESOURCE_GROUP   = terraform output -raw resource_group
$env:AZURE_SUBSCRIPTION_ID  = terraform output -raw subscription_id
$env:AZURE_TENANT_ID        = terraform output -raw tenant_id
$env:AZURE_ZONE_NAME        = $env:TF_VAR_dns_zone
$domain                     = "test.$env:AZURE_ZONE_NAME"
$email                      = "test@$env:AZURE_ZONE_NAME"
&$lego `
  --path tmp/.lego `
  --accept-tos `
  --email $email `
  --domains $domain `
  --dns azure `
  run
```

You should see something alike:

```
[INFO] [test.dev.example.com] acme: Obtaining bundled SAN certificate
[INFO] [test.dev.example.com] AuthURL: https://acme-v02.api.letsencrypt.org/acme/authz-v3/148990933847
[INFO] [test.dev.example.com] acme: Could not find solver for: tls-alpn-01
[INFO] [test.dev.example.com] acme: Could not find solver for: http-01
[INFO] [test.dev.example.com] acme: use dns-01 solver
[INFO] [test.dev.example.com] acme: Preparing to solve DNS-01
[INFO] [test.dev.example.com] acme: Trying to solve DNS-01
[INFO] [test.dev.example.com] acme: Checking DNS record propagation using [google-public-dns-a.google.com:53 google-public-dns-b.google.com:53]
[INFO] Wait for propagation [timeout: 2m0s, interval: 2s]
[INFO] [test.dev.example.com] The server validated our request
[INFO] [test.dev.example.com] acme: Cleaning DNS-01 challenge
[INFO] [test.dev.example.com] acme: Validations succeeded; requesting certificates
[INFO] [test.dev.example.com] Server responded with a certificate.
```

The certificate and related files should be in `tmp/.lego/certificates` as
the following PEM encoded files:

| Filename                        | Description                        |
|---------------------------------|------------------------------------|
| test.dev.example.com.crt        | certificate and intermediate chain |
| test.dev.example.com.issuer.crt | root CA certificate                |
| test.dev.example.com.key        | private key                        |

Inspect the certificate:

```powershell
openssl storeutl -noout -text -certs -in "tmp/.lego/certificates/$domain.crt"
```

You should see something alike:

```
0: Certificate
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            03:a0:a5:e6:07:0d:3b:a0:8f:52:ba:1a:f1:49:e0:65:92:db
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Let's Encrypt, CN=R3
        Validity
            Not Before: Sep  2 16:41:47 2022 GMT
            Not After : Dec  1 16:41:46 2022 GMT
        Subject: CN=test.dev.example.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:19:2f:f5:07:87:a6:b8:fe:b0:48:e7:6d:52:10:
                    b8:c7:64:69:4b:9a:38:48:66:38:92:7d:4c:5d:ba:
                    b1:cf:3c:1d:76:bf:e0:26:5e:bf:ec:1a:a7:45:4b:
                    09:89:d8:ec:f6:8c:68:71:ad:9a:36:0c:f3:f8:72:
                    62:70:67:86:21
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                97:46:7E:6F:E1:1F:D5:D6:2D:FF:86:4D:8E:E0:4F:9E:79:87:6D:5B
            X509v3 Authority Key Identifier:
                14:2E:B3:17:B7:58:56:CB:AE:50:09:40:E6:1F:AF:9D:8B:14:C2:C6
            Authority Information Access:
                OCSP - URI:http://r3.o.lencr.org
                CA Issuers - URI:http://r3.i.lencr.org/
            X509v3 Subject Alternative Name:
                DNS:test.dev.example.com
            X509v3 Certificate Policies:
                Policy: 2.23.140.1.2.1
                Policy: 1.3.6.1.4.1.44947.1.1.1
                  CPS: http://cps.letsencrypt.org
            CT Precertificate SCTs:
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : 41:C8:CA:B1:DF:22:46:4A:10:C6:A1:3A:09:42:87:5E:
                                4E:31:8B:1B:03:EB:EB:4B:C7:68:F0:90:62:96:06:F6
                    Timestamp : Sep  2 17:41:47.931 2022 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:44:02:20:18:71:FA:73:1C:39:05:B5:F6:3D:4C:D8:
                                00:6F:79:76:A4:4D:43:24:44:87:94:E5:F6:C8:61:AC:
                                AA:80:52:2D:02:20:0E:2F:DF:EA:AA:95:B1:F3:F4:C0:
                                4B:47:6F:A3:5E:36:EC:18:90:14:F9:1E:A3:8B:6A:D1:
                                12:2B:5D:F5:C7:33
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : 46:A5:55:EB:75:FA:91:20:30:B5:A2:89:69:F4:F3:7D:
                                11:2C:41:74:BE:FD:49:B8:85:AB:F2:FC:70:FE:6D:47
                    Timestamp : Sep  2 17:41:47.946 2022 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:44:02:20:7D:97:F0:E6:05:D3:B9:78:AF:B3:7D:98:
                                38:CD:D2:65:51:58:6B:8A:94:14:8C:EB:E9:1F:70:D3:
                                6F:08:30:52:02:20:25:7C:65:F6:86:E9:C8:65:F4:5A:
                                CD:91:9D:18:44:53:EA:C6:25:F3:0F:67:05:B8:D8:D8:
                                0E:B8:6E:C5:99:88
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        4e:3a:9c:23:fa:26:2b:df:0e:06:9a:5c:af:eb:d2:cc:37:16:
        51:0c:14:e8:7f:2a:fc:27:32:53:87:59:0a:e7:d3:47:25:3f:
        dc:e8:32:be:11:92:45:72:8c:95:eb:36:f5:91:01:fe:d5:7b:
        c1:1a:20:e6:5c:2c:37:c4:d4:9d:11:da:ba:4c:66:38:8c:d6:
        f9:e7:4f:03:d4:b0:7b:20:15:95:d4:da:e4:50:01:f1:e9:e7:
        8f:52:0e:fd:8b:08:53:2c:19:cf:be:22:cc:fb:48:69:4a:ef:
        2d:7a:33:42:ff:5b:1f:f7:5a:92:6e:3c:e9:52:d8:2a:c7:a0:
        96:01:2c:c9:c1:e6:9e:10:bd:26:ff:00:17:67:5e:4f:32:02:
        68:fe:81:00:b9:89:6f:de:c8:9c:74:c4:19:08:2c:f9:63:98:
        67:88:91:f4:ff:fe:62:fe:1f:a6:2f:e7:40:13:cc:9c:50:c1:
        d2:67:a2:8e:4e:49:e8:9e:24:74:06:18:ba:6f:1b:2b:30:7d:
        f9:1c:7c:3a:29:73:cb:ea:d1:2b:ed:e5:94:3d:3d:f8:0e:1a:
        87:15:cf:2c:73:37:59:64:6f:97:34:55:cd:3b:25:96:30:d0:
        28:84:bb:0a:54:cd:d0:10:3c:42:4e:a1:d8:27:29:89:64:f8:
        54:f8:fe:01
1: Certificate
Certificate:
    ...
```

Destroy everything:

```powershell
terraform destroy
```
