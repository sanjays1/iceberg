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
	"encoding/json"
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
	"go.mozilla.org/pkcs7"

	"github.com/deptofdefense/iceberg/pkg/log"
	"github.com/deptofdefense/iceberg/pkg/policy"
)

const (
	flagListenAddr = "addr"
	flagServerCert = "server-cert"
	flagServerKey  = "server-key"
	flagServerCA   = "server-ca"
	//
	flagRootPath     = "root"
	flagTemplatePath = "template"
	//
	flagPolicyFormat = "format"
	flagPolicyPath   = "policy"
)

func initFlags(flag *pflag.FlagSet) {
	flag.StringP(flagListenAddr, "a", ":8080", "listen address")
	flag.String(flagServerCert, "", "path to server cert")
	flag.String(flagServerKey, "", "path to server key")
	flag.String(flagServerCA, "", "path to server ca")
	flag.StringP(flagRootPath, "r", "", "document root")
	flag.StringP(flagTemplatePath, "t", "", "template path")
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
	serverCert := v.GetString(flagServerCert)
	if len(serverCert) == 0 {
		return fmt.Errorf("server cert is missing")
	}
	serverKey := v.GetString(flagServerKey)
	if len(serverKey) == 0 {
		return fmt.Errorf("server key is missing")
	}
	serverCA := v.GetString(flagServerCA)
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

func serveTemplate(w http.ResponseWriter, r *http.Request, tmpl *template.Template, ctx interface{}) {
	w.Header().Set("Cache-Control", "no-cache")
	err := tmpl.Execute(w, ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("error executing directory listing template for path %q: %w", r.URL.Path, err).Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func serveFile(w http.ResponseWriter, r *http.Request, fs afero.Fs, p string, modtime time.Time, download bool) {
	f, err := fs.Open(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("error opening file from path %q: %w", p, err).Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	if download {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(p)))
	}
	http.ServeContent(w, r, filepath.Base(p), modtime, f)
}

func loadCertPoolFromPkcs7Package(pkcs7Package []byte) (*x509.CertPool, error) {
	p7, err := pkcs7.Parse(pkcs7Package)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	for _, cert := range p7.Certificates {
		certPool.AddCert(cert)
	}
	return certPool, nil
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

func loadPolicy(path string) (*policy.Policy, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading policy from path %q: %w", path, err)
	}
	p := &policy.Policy{}
	err = json.Unmarshal(b, p)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling policy from path %q: %w", path, err)
	}
	return p, nil
}

func newTraceID() string {
	traceID, err := uuid.NewV4()
	if err != nil {
		return ""
	}
	return traceID.String()
}

func main() {
	cmd := &cobra.Command{
		Use:                   `iceberg [flags] -|FILE...`,
		DisableFlagsInUseLine: true,
		Short:                 "iceberg is a file server using client certificate authentication and policy-based access control.",
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

			logger := log.NewSimpleLogger(os.Stdout)

			listenAddress := v.GetString(flagListenAddr)
			rootPath := v.GetString(flagRootPath)

			root := afero.NewBasePathFs(afero.NewReadOnlyFs(afero.NewOsFs()), rootPath)

			serverKeyPair, err := tls.LoadX509KeyPair(v.GetString(flagServerCert), v.GetString(flagServerKey))
			if err != nil {
				return fmt.Errorf("error loading server key pair: %w", err)
			}

			serverCAPath := v.GetString(flagServerCA)

			serverCABytes, err := ioutil.ReadFile(serverCAPath)
			if err != nil {
				return fmt.Errorf("error reading server ca from path %q: %w", serverCAPath, err)
			}

			clientCAs, err := loadCertPoolFromPkcs7Package(serverCABytes)
			if err != nil {
				return fmt.Errorf("error parsing server ca from path %q: %w", serverCAPath, err)
			}

			directoryListingTemplate, err := loadTemplate(v.GetString(flagTemplatePath))
			if err != nil {
				return fmt.Errorf("error loading directory listing template: %w", err)
			}

			accessPolicy, err := loadPolicy(v.GetString(flagPolicyPath))
			if err != nil {
				return fmt.Errorf("error loading policy: %w", err)
			}

			server := &http.Server{
				Addr: listenAddress,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					//user := r.TLS.PeerCertificates[0].Subject.String()
					user := &policy.User{
						Subject: r.TLS.PeerCertificates[0].Subject,
					}
					//
					icebergTraceID := newTraceID()
					//
					logger.Log("Request", map[string]interface{}{
						"url":              r.URL.String(),
						"user_dn":          user.DistinguishedName(),
						"source":           r.RemoteAddr,
						"referer":          r.Header.Get("referer"),
						"host":             r.Host,
						"method":           r.Method,
						"iceberg_trace_id": icebergTraceID,
					})
					//
					p := r.URL.Path

					if !accessPolicy.Evaluate(p, user) {
						logger.Log("Access Denied", map[string]interface{}{
							"url":              r.URL.String(),
							"user_dn":          user.DistinguishedName(),
							"iceberg_trace_id": icebergTraceID,
						})
						http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
						return
					}

					fi, err := root.Stat(p)
					if err != nil {
						if os.IsNotExist(err) {
							logger.Log("Not found", map[string]interface{}{
								"path":             p,
								"iceberg_trace_id": icebergTraceID,
							})
							http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
							return
						}
						logger.Log("Error Stating File", map[string]interface{}{
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
							logger.Log("Error stating index file", map[string]interface{}{
								"path":             indexPath,
								"iceberg_trace_id": icebergTraceID,
							})
							http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
							return
						}
						if os.IsNotExist(err) || indexFileInfo.IsDir() {
							fileInfos, err := afero.ReadDir(root, p)
							if err != nil {
								logger.Log("Error reading directory", map[string]interface{}{
									"path":             p,
									"iceberg_trace_id": icebergTraceID,
								})
								http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
								return
							}
							files := make([]struct {
								ModTime string
								Size    int64
								Path    string
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
							serveTemplate(w, r, directoryListingTemplate, struct {
								Up        string
								Directory string
								Files     []struct {
									ModTime string
									Size    int64
									Path    string
								}
							}{
								Up:        filepath.Dir(p),
								Directory: p,
								Files:     files,
							})
							return
						}
						serveFile(w, r, root, indexPath, time.Time{}, false)
						return
					}
					serveFile(w, r, root, p, fi.ModTime(), true)
					return
				}),
				TLSConfig: &tls.Config{
					ServerName:   "iceberg",
					Certificates: []tls.Certificate{serverKeyPair},
					ClientAuth:   tls.RequireAndVerifyClientCert,
					ClientCAs:    clientCAs,
				},
			}
			fmt.Fprintf(os.Stderr, "Listening on %q\n", listenAddress)
			return server.ListenAndServeTLS("", "")
		},
	}
	initFlags(cmd.Flags())

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "iceberg: "+err.Error())
		fmt.Fprintln(os.Stderr, "Try iceberg --help for more information.")
		os.Exit(1)
	}
}
