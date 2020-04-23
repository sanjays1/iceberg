# iceberg

## Description

`iceberg` is a file server using client certificate authentication and policy-based access control.

## Setup

This project uses [direnv](https://direnv.net/) to manage environment variables.  Install direnv and hook it into your shell.

If using `macOS`, follow the `macOS` instructions below.

### macOS

Install `direnv` with `brew install direnv`.  If using bash, then add `eval \"$(direnv hook bash)\"` to the `~/.bash_profile` file .  If using zsh, then add `eval \"$(direnv hook zsh)\"` to the `~/.zshrc` file.

## Usage

```
iceberg is a file server using client certificate authentication and policy-based access control.

Usage:
  iceberg [flags] -|FILE...

Flags:
  -a, --addr string          listen address (default ":8080")
  -f, --format string        format of the policy file (default "json")
  -h, --help                 help for iceberg
  -p, --policy string        path to the policy file.
  -r, --root string          document root
      --server-ca string     path to server ca
      --server-cert string   path to server cert
      --server-key string    path to server key
  -t, --template string      template path
```

## Examples

```shell
iceberg \
--server-cert temp/server.crt \
--server-key temp/server.key \
--server-ca temp/AllCerts.p7b \
--root examples/public \
-t examples/conf/template.html \
--policy examples/conf/example.json
```

## Contributing

We'd love to have your contributions!  Please see [CONTRIBUTING.md](CONTRIBUTING.md) for more info.

## License

This project constitutes a work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.  However, because the project utilizes code licensed from contributors and other third parties, it therefore is licensed under the MIT License.  See LICENSE file for more information.
