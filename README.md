# certbot-dns-vultr

This package provides a Certbot authenticator plugin
that can complete the DNS-01 challenge using the Vultr API.


## Installation

Use pip to install this package:
```
$ sudo pip3 install certbot-dns-vultr
```

Verify the installation with Certbot:
```
$ sudo certbot plugins
```
You should see `certbot-dns-vultr:dns-vultr` in the output.


## Usage

To use this plugin, set the authenticator to `certbot-dns-vultr:dns-vultr` via the `-a` or `--authenticator` flag.
You may also set this using Certbot's configuration file (defaults to `/etc/letsencrypt/cli.ini`).

You will also need to provide a credentials file with your Vultr API key, like the following:
```
certbot_dns_vultr:dns_vultr_key = YOUR_VULTR_API_KEY
```
The path to this file can be provided interactively or via the `--certbot-dns-vultr:dns-vultr-credentials` argument.

**CAUTION:**
Protect your API key as you would the password to your account.
Anyone with access to this file can make API calls on your behalf.
Be sure to **read the security tips below**.


### Arguments

- `--certbot-dns-vultr:dns-vultr-credentials` path to Vultr credentials INI file (Required)
- `--certbot-dns-vultr:dns-vultr-propagation-seconds` seconds to wait before verifying the DNS record (Default: 10)

**NOTE:** Due to a [limitation in Certbot](https://github.com/certbot/certbot/issues/4351),
these arguments *cannot* be set via Certbot's configuration file.


### Example

```
$ certbot certonly \
    -a certbot-dns-vultr:dns-vultr \
    --certbot-dns-vultr:dns-vultr-credentials ~/.secrets/certbot/vultr.ini \
    -d example.com
```


### Security Tips

**Restrict access of your credentials file to the owner.**
You can do this using `chmod 600`.
Certbot will emit a warning if the credentials file
can be accessed by other users on your system.

**Use a separate key from your account's primary API key.**
Make a separate user under your account,
and limit its access to only allow DNS access
and the IP address of the machine(s) that will be using it.
