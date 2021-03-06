# iceberg

## Description

**iceberg** is a file server that uses client certificate authentication and policy-based access control.  iceberg requires the use of client certificates verified with the certificate authority chain configured at startup.

Iceberg is built in [Go](https://golang.org/). Iceberg uses the [net/http](https://pkg.go.dev/net/http) and [crypto/tls](https://pkg.go.dev/crypto/tls#Config) packages in the Go standard library to secure communication.  By default, iceberg supports TLS 1.0 to 1.3 and all the [CipherSuites](https://pkg.go.dev/crypto/tls?tab=doc#CipherSuites) implemented by `net/http`, excluding those with known security issues.  The TLS configuration can be modified using command line flags.

Iceberg is an alternative to configuring the [Apache HTTP Server](https://httpd.apache.org/) or [NGINX](https://www.nginx.com/) to serve files while requiring client certificates.  Iceberg does not attempt to be on parity with other file servers, but is designed to be a file server that is simple to manage and secure by default.

## Usage

The `iceberg` program has 5 sub commands: `defaults`, `help`, `serve`, `validate-access-policy`, and `version`.  Use `iceberg serve` to launch the server and `iceberg validate-access-policy` to validate a policy file.  Use `iceberg defaults [tls-cipher-suites|tls-curve-preferences]` to show default configuration.  Use `iceberg version` to show the current version.

Below is the usage for the `iceberg serve` command.

```text
start the iceberg server

Usage:
  iceberg serve [flags]

Flags:
  -p, --access-policy string              path to the policy file.
  -f, --access-policy-format string       format of the policy file (default "json")
  -a, --addr string                       address that iceberg will listen on (default ":8080")
      --behavior-not-found string         default behavior when a file is not found.  One of: redirect,none (default "none")
      --client-ca string                  path to CA bundle for client authentication
      --client-ca-format string           format of the CA bundle for client authentication, either pkcs7 or pem (default "pkcs7")
      --dry-run                           exit after checking configuration
  -h, --help                              help for serve
  -l, --log string                        path to the log output.  Defaults to stdout. (default "-")
      --public-location string            the public location of the server used for redirects
      --redirect string                   address that iceberg will listen to and redirect requests to the public location
  -r, --root string                       path to the document root served
      --server-cert string                path to server public cert
      --server-key string                 path to server private key
  -t, --template string                   path to the template file used during directory listing
      --timeout-idle string               maximum amount of time to wait for the next request when keep-alives are enabled (default "5m")
      --timeout-read string               maximum duration for reading the entire request (default "15m")
      --timeout-write string              maximum duration before timing out writes of the response (default "5m")
      --tls-cipher-suites string          list of supported cipher suites for TLS versions up to 1.2 (TLS 1.3 is not configureable)
      --tls-curve-preferences string      curve preferences (default "X25519,CurveP256,CurveP384,CurveP521")
      --tls-max-version string            maximum TLS version accepted for requests (default "1.3")
      --tls-min-version string            minimum TLS version accepted for requests (default "1.0")
      --tls-prefer-server-cipher-suites   prefer server cipher suites
```

### Network Encryption

**iceberg** requires the use of a server certificate and client certificate authentication.  The server certificate is loaded from a PEM-encoded x509 key pair using the [LoadX509KeyPair](https://golang.org/pkg/crypto/tls/#LoadX509KeyPair) function.  The location of the key pair is specified using the `--server-cert` and `--server-key` command line flags.

The client certificate authorities can be loaded from a [PKCS#7](https://en.wikipedia.org/wiki/PKCS) or PEM-encoded file.  The [Parse](https://pkg.go.dev/go.mozilla.org/pkcs7#Parse) function in [go.mozilla.org/pkcs7](https://pkg.go.dev/go.mozilla.org/pkcs7) is used to parse the PKCS#7-encoded data loaded from a `.p7b` file.  The [AppendCertsFromPEM](https://pkg.go.dev/crypto/x509#CertPool.AppendCertsFromPEM) method is used to parse PEM-encoded data loaded from a `.pem` file.  The location of the client certificate authorities is specified using the `client-ca` and `client-ca-format` command line flags.

You can use the `tls-*` flags to customize the server TLS configuration.  Options are very limited for [TLS 1.3](https://github.com/golang/go/issues/29349).

For example, you could configure the server to only support TLS version `1.2` and specific ciphers using `--tls-min-version`, `--tls-max-version`, and `--tls-cipher-suites`.

```shell
iceberg serve ... --tls-min-version 1.2 --tls-max-version 1.2 --tls-cipher-suites 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
```

Mozilla keeps a [Security/Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS) document up to date on the best practices for configuring a server for TLS.

### Access Policy Document

An access policy document is a list of statements that are evaluate when determining whether a user can access a given file path.  By default, users have no privileges.  The access policy document can be serialized as a JSON or YAML document.

```json
{
  "statements": [...]
}
```

The policy statements are evaluated sequentially.  If the first policy statement allows access, the other statements are still evaluated.  If any statement denies access, then the user is denied access.

Each statement requires the `effect`, `paths`, and `users`/`not_users` to be set.  The id is optional and not used during evaluation.  The effect is either `allow` or `deny`.

```json
{
  "id": "DefaultAllow",
  "effect": "allow",
  "paths": [...],
  "users": [...],
  "not_users": [],
}
```

The values for `paths` includes an array of paths from the root directory as set during startup, e.g., `/shared`.  Paths can start or end with a `wildcard`, eg., `/shared/*` or `*.jpg`.

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
    Type    string
    Path    string
  }
})
```

## Examples

Below are the example commands and files needed to run a server that, by default allows access to all files, but limits access to the `/secure` path to a limited set of users identified by their client certificate subject distinguished name.

```shell
iceberg serve \
--access-policy examples/conf/example.json \
--client-ca temp/certs.p7b \
--root examples/public \
--server-cert temp/server.crt \
--server-key temp/server.key \
--template examples/conf/template.html \
--behavior-not-found redirect
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

To build a binary for your local operating system you can use `make bin/iceberg`.  To build for a release, you can use `make build_release`.  Additionally, you can call `go build` directly to support specific use cases.

### macOS

You can install `go` on macOS using homebrew with `brew install go`.

To install `direnv` on `macOS` use `brew install direnv`.  If using bash, then add `eval \"$(direnv hook bash)\"` to the `~/.bash_profile` file .  If using zsh, then add `eval \"$(direnv hook zsh)\"` to the `~/.zshrc` file.

## Contributing

We'd love to have your contributions!  Please see [CONTRIBUTING.md](CONTRIBUTING.md) for more info.

## Security

Please see [SECURITY.md](SECURITY.md) for more info.

## License

This project constitutes a work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.  However, because the project utilizes code licensed from contributors and other third parties, it therefore is licensed under the MIT License.  See LICENSE file for more information.
