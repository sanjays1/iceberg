# iceberg

## Description

**iceberg** is a file server using client certificate authentication and policy-based access control.  iceberg requires the use of client certificates verified with the certificate authority chain configured at startup.

**iceberg** is built in [Go](https://golang.org/). iceberg uses the [net/http package](http://godoc.org/pkg/net/http) and [crypto/tls](https://godoc.org/crypto/tls#Config) packages in the Go standard library to secure communication.

## Usage

The `iceberg` program has 3 sub commands: `help`, `serve`, and `validate-policy`.  Use `iceberg serve` to launch the server and `iceberg validate-policy` to validate a policy file.  Below is the usage for the `iceberg serve` command.

```text
start the iceberg server

Usage:
  iceberg serve [flags]

Flags:
  -a, --addr string               address that iceberg will listen on (default ":8080")
      --client-ca string          path to CA bundle for client authentication
      --client-ca-format string   format of the CA bundle for client authentication, either pkcs7 or pem (default "pkcs7")
  -f, --format string             format of the policy file (default "json")
  -h, --help                      help for serve
  -l, --log string                path to the log output.  Defaults to stdout. (default "-")
  -p, --policy string             path to the policy file.
      --public-location string    the public location of the server used for redirects
      --redirect string           address that iceberg will listen to and redirect requests to the public location
  -r, --root string               path to the document root served
      --server-cert string        path to server public cert
      --server-key string         path to server private key
  -t, --template string           path to the template file used during directory listing
      --timeout-idle string       maximum amount of time to wait for the next request when keep-alives are enabled (default "5m")
      --timeout-read string       maximum duration for reading the entire request (default "5m")
      --timeout-write string      maximum duration before timing out writes of the response (default "5m")
```

### Network Encryption

**iceberg** requires the use of a server certificate and client certificate authentication.  The server certificate is loaded from a PEM-encoded x509 key pair using the [LoadX509KeyPair](https://golang.org/pkg/crypto/tls/#LoadX509KeyPair) function.  The location of the key pair is specified using the `--server-cert` and `--server-key` command line flags.

The client certificate authorities can be loaded from a [PKCS#7](https://en.wikipedia.org/wiki/PKCS) or PEM-encoded file.  The [Parse](https://godoc.org/go.mozilla.org/pkcs7#Parse) function in [go.mozilla.org/pkcs7](https://godoc.org/go.mozilla.org/pkcs7) is used to parse the PKCS#7-encoded data loaded from a `.p7b` file.  The [AppendCertsFromPEM](https://godoc.org/crypto/x509#CertPool.AppendCertsFromPEM) method is used to parse PEM-encoded data loaded from a `.pem` file.  The location of the client certificate authorities is specified using the `client-ca` and `client-ca-format` command line flags.

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
    "/C=US/O=Atlantis/OU=Atlantis Digital Service/OU=CONTRACTOR/CN=LAST.FIRST.MIDDLE.ID"
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
iceberg serve \
--server-cert temp/server.crt \
--server-key temp/server.key \
--client-ca temp/certs.p7b \
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
        "/C=US/O=Atlantis/OU=Atlantis Digital Service/OU=CONTRACTOR/CN=LAST.FIRST.MIDDLE.ID",
      ]
    }
  ]
}
```

## Building

**iceberg** is written in pure Go, so the only dependency needed to compile the server is [Go](https://golang.org/).  Go can be downloaded from <https://golang.org/dl/>.

This project uses [direnv](https://direnv.net/) to manage environment variables and automatically adding the `bin` and `scripts` folder to the path.  Install direnv and hook it into your shell.  The use of `direnv` is optional as you can always call iceberg directly with `bin/iceberg`.

If using `macOS`, follow the `macOS` instructions below.

To build the binary you can use the make targets `bin/iceberg`, `bin_linux/iceberg`, `bin/bin_darwin_static/iceberg`, `bin/bin_linux_static/iceberg`.  Alternatively, you can call `go build` directly for specific use cases.

### macOS

You can install `go` on macOS using homebrew with `brew install go`.

To install `direnv` on `macOS` use `brew install direnv`.  If using bash, then add `eval \"$(direnv hook bash)\"` to the `~/.bash_profile` file .  If using zsh, then add `eval \"$(direnv hook zsh)\"` to the `~/.zshrc` file.

## Contributing

We'd love to have your contributions!  Please see [CONTRIBUTING.md](CONTRIBUTING.md) for more info.

## Security

Please see [SECURITY.md](SECURITY.md) for more info.

## License

This project constitutes a work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.  However, because the project utilizes code licensed from contributors and other third parties, it therefore is licensed under the MIT License.  See LICENSE file for more information.
