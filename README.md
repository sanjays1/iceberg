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
timebucket is used to create histograms from temporal data.

Usage:
  timebucket [flags] -|FILE...

Flags:
  -h, --help                   help for timebucket
      --input-column string    input column
      --input-format string    input format (default "csv")
      --key-format string      hash key format
      --layouts string         default layouts
      --limit int              maximum number of records to process (default -1)
      --output-format string   output format (default "csv")
```

## Examples

```shell
iceberg --root /var/www --policy /etc/iceberg/policy.json
```

## Contributing

We'd love to have your contributions!  Please see [CONTRIBUTING.md](CONTRIBUTING.md) for more info.

## License

This project constitutes a work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.  However, because the project utilizes code licensed from contributors and other third parties, it therefore is licensed under the MIT License.  See LICENSE file for more information.
