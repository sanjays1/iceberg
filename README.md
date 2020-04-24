# iceberg

## Description

*iceberg* is a file server using client certificate authentication and policy-based access control.  iceberg requires the use of client certificates verified with the certificate authority chain configured at startup.

*iceberg* is built in [Go](https://golang.org/). iceberg uses the [net/http package](http://godoc.org/pkg/net/http) and [crypto/tls](https://godoc.org/crypto/tls#Config) packages in the Go standard library to secure communication.

## Usage

```
iceberg is a file server using client certificate authentication and policy-based access control.

Usage:
  iceberg [flags]

Flags:
  -a, --addr string               address that iceberg will listen on (default ":8080")
  -f, --format string             format of the policy file (default "json")
  -h, --help                      help for iceberg
  -p, --policy string             path to the policy file.
  -r, --root string               path to the document root served
      --server-ca string          path to server CA bundle for client auth
      --server-ca-format string   format of the server CA bundle for client auth, either pkcs7 or pem (default "pkcs7")
      --server-cert string        path to server public cert
      --server-key string         path to server private key
  -t, --template string           path to the template file used during directory listing
```

### Policy Document

A policy document is a list of statements that are evaluate when determining whether a user can access a given file path.  By default, users have no privileges.  The policy document can be serialized as a JSON or YAML document.

```json
{
  "statements": [...]
}
```

The policy statements are evaluated sequentially.  Every policy statement is evaluated.  If the first policy statement allows access, the other statements are still evaluated.  If any statement denies access, then the user is denied access.

Each statement requires the effect, paths, and users to be set.  The id is optional and not used during evaluation.  The effect is either `allow` or `deny`.

```json
{
  "id": "DefaultAllow",
  "effect": "allow",
  "paths": [...],
  "users": [...],
  "not_users": [],
}
```

The values for `paths` includes an array of paths from the root directory as set during startup, e.g., `/shared`.  Paths can end with a `wildcard`, eg., `/shared/*`, which matches any contained file or directory.

```json
{
  "paths": [
    "/shared/",
    "/shared/*"
  ]
}
```

The value for `paths` can be set to `["*"]` to apply to all file paths.

```json
{
  "paths": ["*"]
}
```

The values included in `users` or `not_users` includes an array of distinguished names derived from the the subject of the client certificate provided by the connecting client.  The value of `not_users` means the statement effect is applied to any user not in the array.  For example.

```json
{
  "users": [
    "/C=US/O=U.S. Government/OU=DoD/OU=PKI/OU=CONTRACTOR/CN=LAST.FIRST.MIDDLE.EDIPI",
  ]
}
```

The value for `users` can be set to `["*"]` to apply to all users.

```json
{
  "users": ["*"]
}
```

### Directory Listing Template

The template provided during server startup is used to render directory listings using the native Go template rendering engine in the [html/template](https://golang.org/pkg/html/template/) package.  The template is provided the following context.

```go
struct {
  Up        string
  Directory string
  Files     []struct {
    ModTime string
    Size    int64
    Path    string
  }
})
```

## Examples

Below are the example commands and files needed to run a server that, by default allows access to all files, but limits access to the `/secure` path to a limited set of users identified by their client certificate subject distinguished name.

```shell
iceberg \
--server-cert temp/server.crt \
--server-key temp/server.key \
--server-ca temp/AllCerts.p7b \
--root examples/public \
-t examples/conf/template.html \
--policy examples/conf/example.json
```

The below policy statement allows access to any authenticated user and then limits access to `/secure` to a limited set of users.

```json
{
  "statements": [
    {
      "id": "DefaultAllow",
      "effect": "allow",
      "paths": [
        "*"
      ],
      "users": [
        "*"
      ]
    },
    {
      "id": "ProtectSecure",
      "effect": "deny",
      "paths": [
        "/secure",
        "/secure/*"
      ],
      "not_users": [
        "/C=US/O=U.S. Government/OU=DoD/OU=PKI/OU=CONTRACTOR/CN=LAST.FIRST.MIDDLE.EDIPI",
      ]
    }
  ]
}
```

## Building

iceberg is a pure-golang server, so the only dependency needed to compile the server is the golang installation.  Go can be downloaded from <https://golang.org/dl/>.  This project uses [direnv](https://direnv.net/) to manage environment variables.  Install direnv and hook it into your shell.

If using `macOS`, follow the `macOS` instructions below.

To build the binary you can use the make targets `bin/iceberg`, `bin_linux/iceberg`, `bin/bin_darwin_static/iceberg`, `bin/bin_linux_static/iceberg`.  Alternatively, you can call `go build` directly for specific use cases.

### macOS

You can install `go` on macOS using homebrew with `brew install go`.

Install `direnv` with `brew install direnv`.  If using bash, then add `eval \"$(direnv hook bash)\"` to the `~/.bash_profile` file .  If using zsh, then add `eval \"$(direnv hook zsh)\"` to the `~/.zshrc` file.

## Contributing

We'd love to have your contributions!  Please see [CONTRIBUTING.md](CONTRIBUTING.md) for more info.

## License

This project constitutes a work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.  However, because the project utilizes code licensed from contributors and other third parties, it therefore is licensed under the MIT License.  See LICENSE file for more information.
