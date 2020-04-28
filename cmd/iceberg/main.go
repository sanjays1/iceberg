// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/deptofdefense/iceberg/pkg/certs"
	"github.com/deptofdefense/iceberg/pkg/log"
	"github.com/deptofdefense/iceberg/pkg/policy"
	"github.com/deptofdefense/iceberg/pkg/server"
)

const (
	flagListenAddr     = "addr"
	flagRedirectAddr   = "redirect"
	flagPublicLocation = "public-location"
	//
	flagServerCert = "server-cert"
	flagServerKey  = "server-key"
	//
	flagClientCAFormat = "client-ca-format"
	flagClientCA       = "client-ca"
	//
	flagRootPath     = "root"
	flagTemplatePath = "template"
	//
	flagPolicyFormat = "format"
	flagPolicyPath   = "policy"
	//
	flagLogPath = "log"
)

func initFlags(flag *pflag.FlagSet) {
	flag.String(flagPublicLocation, "", "the public location of the server used for redirects")
	flag.StringP(flagListenAddr, "a", ":8080", "address that iceberg will listen on")
	flag.String(flagRedirectAddr, "", "address that iceberg will listen to and redirect requests to the public location")
	flag.String(flagServerCert, "", "path to server public cert")
	flag.String(flagServerKey, "", "path to server private key")
	flag.String(flagClientCAFormat, "pkcs7", "format of the CA bundle for client authentication, either pkcs7 or pem")
	flag.String(flagClientCA, "", "path to CA bundle for client authentication")
	flag.StringP(flagRootPath, "r", "", "path to the document root served")
	flag.StringP(flagTemplatePath, "t", "", "path to the template file used during directory listing")
	flag.StringP(flagLogPath, "l", "-", "path to the log output.  Defaults to stdout.")
	initPolicyFlags(flag)
}

func initPolicyFlags(flag *pflag.FlagSet) {
	flag.StringP(flagPolicyFormat, "f", "json", "format of the policy file")
	flag.StringP(flagPolicyPath, "p", "", "path to the policy file.")
}

func initViper(cmd *cobra.Command) (*viper.Viper, error) {
	v := viper.New()
	err := v.BindPFlags(cmd.Flags())
	if err != nil {
		return v, fmt.Errorf("error binding flag set to viper: %w", err)
	}
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv() // set environment variables to overwrite config
	return v, nil
}

func checkConfig(v *viper.Viper) error {
	addr := v.GetString(flagListenAddr)
	if len(addr) == 0 {
		return fmt.Errorf("listen address is missing")
	}
	redirectAddress := v.GetString(flagRedirectAddr)
	if len(redirectAddress) > 0 {
		publicLocation := v.GetString(flagPublicLocation)
		if len(publicLocation) == 0 {
			return fmt.Errorf("public location is required when redirecting")
		}
		if !strings.HasPrefix(publicLocation, "https://") {
			return fmt.Errorf("public location must start with \"https://\"")
		}
	}
	serverCert := v.GetString(flagServerCert)
	if len(serverCert) == 0 {
		return fmt.Errorf("server cert is missing")
	}
	serverKey := v.GetString(flagServerKey)
	if len(serverKey) == 0 {
		return fmt.Errorf("server key is missing")
	}
	serverCA := v.GetString(flagClientCA)
	if len(serverCA) == 0 {
		return fmt.Errorf("server CA is missing")
	}
	rootPath := v.GetString(flagRootPath)
	if len(rootPath) == 0 {
		return fmt.Errorf("root path is missing")
	}
	templatePath := v.GetString(flagTemplatePath)
	if len(templatePath) == 0 {
		return fmt.Errorf("template path is missing")
	}
	if err := checkPolicyConfig(v); err != nil {
		return fmt.Errorf("invalid policy configuration: %w", err)
	}
	logPath := v.GetString(flagLogPath)
	if len(logPath) == 0 {
		return fmt.Errorf("log path is missing")
	}
	return nil
}

func checkPolicyConfig(v *viper.Viper) error {
	policyFormat := v.GetString(flagPolicyFormat)
	if len(policyFormat) == 0 {
		return fmt.Errorf("policy format is missing")
	}
	policyPath := v.GetString(flagPolicyPath)
	if len(policyPath) == 0 {
		return fmt.Errorf("policy path is missing")
	}
	return nil
}

func loadTemplate(p string) (*template.Template, error) {
	b, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("error loading template from file %q: %w", p, err)
	}
	t, err := template.New("main").Parse(string(b))
	if err != nil {
		return nil, fmt.Errorf("error parsing template from file %q: %w", p, err)
	}
	return t, nil
}

func newTraceID() string {
	traceID, err := uuid.NewV4()
	if err != nil {
		return ""
	}
	return traceID.String()
}

func initLogger(path string) (*log.SimpleLogger, error) {

	if path == "-" {
		return log.NewSimpleLogger(os.Stdout), nil
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("error opening log file %q: %w", path, err)
	}

	return log.NewSimpleLogger(f), nil
}

func main() {

	rootCommand := &cobra.Command{
		Use:                   `iceberg [flags]`,
		DisableFlagsInUseLine: true,
		Short:                 "iceberg is a file server using client certificate authentication and policy-based access control.",
	}

	validatePolicyCommand := &cobra.Command{
		Use:                   `validate-policy [--policy POLICY_FILE] [--policy-format POLICY_FORMAT]`,
		DisableFlagsInUseLine: true,
		Short:                 "validate the iceberg access policy file",
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := initViper(cmd)
			if err != nil {
				return fmt.Errorf("error initializing viper: %w", err)
			}

			if len(args) > 1 {
				return cmd.Usage()
			}

			if errConfig := checkPolicyConfig(v); errConfig != nil {
				return errConfig
			}

			accessPolicyDocument, err := policy.Parse(v.GetString(flagPolicyPath), v.GetString(flagPolicyFormat))
			if err != nil {
				return fmt.Errorf("error loading policy: %w", err)
			}

			err = accessPolicyDocument.Validate()
			if err != nil {
				return fmt.Errorf("error validating policy: %w", err)
			}

			return nil
		},
	}
	initFlags(validatePolicyCommand.Flags())

	serveCommand := &cobra.Command{
		Use:                   `serve [flags]`,
		DisableFlagsInUseLine: true,
		Short:                 "start the iceberg server",
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := initViper(cmd)
			if err != nil {
				return fmt.Errorf("error initializing viper: %w", err)
			}

			if len(args) > 1 {
				return cmd.Usage()
			}

			if errConfig := checkConfig(v); errConfig != nil {
				return errConfig
			}

			logger, err := initLogger(v.GetString(flagLogPath))
			if err != nil {
				return fmt.Errorf("error initializing logger: %w", err)
			}

			listenAddress := v.GetString(flagListenAddr)
			redirectAddress := v.GetString(flagRedirectAddr)
			publicLocation := v.GetString(flagPublicLocation)
			rootPath := v.GetString(flagRootPath)

			root := afero.NewBasePathFs(afero.NewReadOnlyFs(afero.NewOsFs()), rootPath)

			serverKeyPair, err := tls.LoadX509KeyPair(v.GetString(flagServerCert), v.GetString(flagServerKey))
			if err != nil {
				return fmt.Errorf("error loading server key pair: %w", err)
			}

			clientCAs, err := certs.LoadCertPool(v.GetString(flagClientCA), v.GetString(flagClientCAFormat))
			if err != nil {
				return fmt.Errorf("error loading client certificate authority: %w", err)
			}

			directoryListingTemplate, err := loadTemplate(v.GetString(flagTemplatePath))
			if err != nil {
				return fmt.Errorf("error loading directory listing template: %w", err)
			}

			accessPolicyDocument, err := policy.Parse(v.GetString(flagPolicyPath), v.GetString(flagPolicyFormat))
			if err != nil {
				return fmt.Errorf("error loading policy: %w", err)
			}

			err = accessPolicyDocument.Validate()
			if err != nil {
				return fmt.Errorf("error validating policy: %w", err)
			}

			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{serverKeyPair},
				ClientAuth:   tls.RequireAnyClientCert,
				ClientCAs:    clientCAs,
			}

			httpsServer := &http.Server{
				Addr:      listenAddress,
				TLSConfig: tlsConfig,
				ErrorLog:  log.WrapStandardLogger(logger),
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					//
					icebergTraceID := newTraceID()
					//
					peerCertificates := r.TLS.PeerCertificates
					if len(peerCertificates) == 0 {
						_ = logger.Log("Missing client certificate", map[string]interface{}{
							"iceberg_trace_id": icebergTraceID,
							"url":              r.URL.String(),
						})
						http.Error(w, "Missing client certificate", http.StatusBadRequest)
						return
					}
					intermediates := x509.NewCertPool()
					for _, c := range peerCertificates[1:] {
						intermediates.AddCert(c)
					}
					verifiedChains, err := peerCertificates[0].Verify(x509.VerifyOptions{
						Roots:         clientCAs,
						Intermediates: intermediates,
						KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
					})
					if err != nil {
						_ = logger.Log("Certificate denied", map[string]interface{}{
							"iceberg_trace_id": icebergTraceID,
							"url":              r.URL.String(),
							"error":            err.Error(),
							"subjects":         certs.Subjects(peerCertificates),
							"issuers":          certs.Issuers(peerCertificates),
						})
						http.Error(w, "Could not verify client certificate", http.StatusForbidden)
						return
					} else {
						_ = logger.Log("Certificate verified", map[string]interface{}{
							"iceberg_trace_id": icebergTraceID,
							"url":              r.URL.String(),
							"subjects":         certs.Subjects(peerCertificates),
							"issuers":          certs.Issuers(peerCertificates),
						})
					}
					//
					user := &policy.User{
						Subject: verifiedChains[0][0].Subject,
						//Subject: r.TLS.VerifiedChains[0][0].Subject,
						//Subject: r.TLS.PeerCertificates[0].Subject,
					}
					//
					_ = logger.Log("Request", map[string]interface{}{
						"url":              r.URL.String(),
						"user_dn":          user.DistinguishedName(),
						"source":           r.RemoteAddr,
						"referer":          r.Header.Get("referer"),
						"host":             r.Host,
						"method":           r.Method,
						"iceberg_trace_id": icebergTraceID,
					})

					// Get path from URL
					p := server.TrimTrailingForwardSlash(server.CleanPath(r.URL.Path))

					// If path is not clean
					if !server.CheckPath(p) {
						_ = logger.Log("Invalid path", map[string]interface{}{
							"user_dn":          user.DistinguishedName(),
							"iceberg_trace_id": icebergTraceID,
							"url":              r.URL.String(),
							"path":             p,
						})
						http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
						return
					}

					if !accessPolicyDocument.Evaluate(p, user) {
						_ = logger.Log("Access denied", map[string]interface{}{
							"user_dn":          user.DistinguishedName(),
							"iceberg_trace_id": icebergTraceID,
							"url":              r.URL.String(),
						})
						http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
						return
					} else {
						_ = logger.Log("Access allowed", map[string]interface{}{
							"user_dn":          user.DistinguishedName(),
							"iceberg_trace_id": icebergTraceID,
							"url":              r.URL.String(),
						})
					}

					fi, err := root.Stat(p)
					if err != nil {
						if os.IsNotExist(err) {
							_ = logger.Log("Not found", map[string]interface{}{
								"path":             p,
								"iceberg_trace_id": icebergTraceID,
							})
							http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
							return
						}
						_ = logger.Log("Error stating file", map[string]interface{}{
							"path":             p,
							"iceberg_trace_id": icebergTraceID,
						})
						http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
						return
					}
					if fi.IsDir() {
						indexPath := filepath.Join(p, "index.html")
						indexFileInfo, err := root.Stat(indexPath)
						if err != nil && !os.IsNotExist(err) {
							_ = logger.Log("Error stating index file", map[string]interface{}{
								"path":             indexPath,
								"iceberg_trace_id": icebergTraceID,
							})
							http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
							return
						}
						if os.IsNotExist(err) || indexFileInfo.IsDir() {
							fileInfos, err := afero.ReadDir(root, p)
							if err != nil {
								_ = logger.Log("Error reading directory", map[string]interface{}{
									"path":             p,
									"iceberg_trace_id": icebergTraceID,
								})
								http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
								return
							}
							files := make([]struct {
								ModTime string //lint:ignore U1000 slice is appended to
								Size    int64  //lint:ignore U1000 slice is appended to
								Path    string //lint:ignore U1000 slice is appended to
							}, 0, len(fileInfos))
							for _, fi := range fileInfos {
								files = append(files, struct {
									ModTime string
									Size    int64
									Path    string
								}{
									ModTime: fi.ModTime().In(time.UTC).Format(time.RFC3339),
									Size:    fi.Size(),
									Path:    filepath.Join(p, fi.Name()),
								})
							}
							server.ServeTemplate(w, r, directoryListingTemplate, struct {
								Up        string
								Directory string
								Files     []struct {
									ModTime string //lint:ignore U1000 slice is set
									Size    int64  //lint:ignore U1000 slice is set
									Path    string //lint:ignore U1000 slice is set
								}
							}{
								Up:        filepath.Dir(p),
								Directory: p,
								Files:     files,
							})
							return
						}
						server.ServeFile(w, r, root, indexPath, time.Time{}, false)
						return
					}
					server.ServeFile(w, r, root, p, fi.ModTime(), true)
				}),
			}
			//
			if len(redirectAddress) > 0 && len(publicLocation) > 0 {
				httpServer := &http.Server{
					Addr:     redirectAddress,
					ErrorLog: log.WrapStandardLogger(logger),
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						_ = logger.Log("Redirecting request", map[string]interface{}{
							"iceberg_trace_id": newTraceID(),
							"url":              r.URL.String(),
							"target":           publicLocation,
						})
						http.Redirect(w, r, publicLocation, http.StatusSeeOther)
					}),
				}
				_, _ = fmt.Fprintf(os.Stderr, "Redirecting %q to %q\n", redirectAddress, publicLocation)
				go func() { _ = httpServer.ListenAndServe() }()
			}
			//
			_, _ = fmt.Fprintf(os.Stderr, "Listening on %q\n", listenAddress)
			return httpsServer.ListenAndServeTLS("", "")
		},
	}
	initFlags(serveCommand.Flags())

	rootCommand.AddCommand(validatePolicyCommand, serveCommand)

	if err := rootCommand.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "iceberg: "+err.Error())
		_, _ = fmt.Fprintln(os.Stderr, "Try iceberg --help for more information.")
		os.Exit(1)
	}
}
