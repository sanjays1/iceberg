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
	"sort"
	"strconv"
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
	TLSVersion1_0 = "1.0"
	TLSVersion1_1 = "1.1"
	TLSVersion1_2 = "1.2"
	TLSVersion1_3 = "1.3"
)

var (
	SupportedTLSVersions = []string{
		TLSVersion1_0,
		TLSVersion1_1,
		TLSVersion1_2,
		TLSVersion1_3,
	}
	TLSVersionIdentifiers = map[string]uint16{
		TLSVersion1_0: tls.VersionTLS10,
		TLSVersion1_1: tls.VersionTLS11,
		TLSVersion1_2: tls.VersionTLS12,
		TLSVersion1_3: tls.VersionTLS13,
	}
)

const (
	CurveP256 = "CurveP256"
	CurveP384 = "CurveP384"
	CurveP521 = "CurveP521"
	X25519    = "X25519"
)

const (
	BehaviorRedirect = "redirect"
	BehaviorNone     = "none"
)

var (
	Behaviors = []string{
		BehaviorRedirect,
		BehaviorNone,
	}
)

var (
	DefaultCurveIDs = []string{
		X25519,
		CurveP256,
		CurveP384,
		CurveP521,
	}
	SupportedCurveIDs = []string{
		CurveP256,
		CurveP384,
		CurveP521,
		X25519,
	}
	TLSCurveIdentifiers = map[string]tls.CurveID{
		CurveP256: tls.CurveP256,
		CurveP384: tls.CurveP384,
		CurveP521: tls.CurveP521,
		X25519:    tls.X25519,
	}
)

func stringSliceContains(stringSlice []string, value string) bool {
	for _, x := range stringSlice {
		if value == x {
			return true
		}
	}
	return false
}

func stringSliceIndex(stringSlice []string, value string) int {
	for i, x := range stringSlice {
		if value == x {
			return i
		}
	}
	return -1
}

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
	flagAccessPolicyFormat = "access-policy-format"
	flagAccessPolicyPath   = "access-policy"
	//
	flagTimeoutRead  = "timeout-read"
	flagTimeoutWrite = "timeout-write"
	flagTimeoutIdle  = "timeout-idle"
	//
	flagTLSMinVersion = "tls-min-version"
	flagTLSMaxVersion = "tls-max-version"
	//flagTLSCipherSuites = "tls-cipher-suites"
	flagTLSCurvePreferences = "tls-curve-preferences"
	//
	flagBehaviorNotFound = "behavior-not-found"
	//
	flagLogPath = "log"
)

type File struct {
	ModTime string
	Size    int64
	Type    string
	Path    string
}

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
	flag.String(flagBehaviorNotFound, BehaviorNone, "default behavior when a file is not found.  One of: "+strings.Join(Behaviors, ","))
	initPolicyFlags(flag)
	initTimeoutFlags(flag)
	initTLSFlags(flag)
}

func initTimeoutFlags(flag *pflag.FlagSet) {
	flag.String(flagTimeoutRead, "15m", "maximum duration for reading the entire request")
	flag.String(flagTimeoutWrite, "5m", "maximum duration before timing out writes of the response")
	flag.String(flagTimeoutIdle, "5m", "maximum amount of time to wait for the next request when keep-alives are enabled")
}

func initTLSFlags(flag *pflag.FlagSet) {
	flag.String(flagTLSMinVersion, TLSVersion1_0, "minimum TLS version accepted for requests")
	flag.String(flagTLSMaxVersion, TLSVersion1_3, "maximum TLS version accepted for requests")
	flag.String(flagTLSCurvePreferences, strings.Join(DefaultCurveIDs, ","), "curve preferences")
}

func initPolicyFlags(flag *pflag.FlagSet) {
	flag.StringP(flagAccessPolicyFormat, "f", "json", "format of the policy file")
	flag.StringP(flagAccessPolicyPath, "p", "", "path to the policy file.")
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
	if err := checkAccessPolicyConfig(v); err != nil {
		return fmt.Errorf("invalid access policy configuration: %w", err)
	}
	logPath := v.GetString(flagLogPath)
	if len(logPath) == 0 {
		return fmt.Errorf("log path is missing")
	}
	timeoutRead := v.GetString(flagTimeoutRead)
	if len(timeoutRead) == 0 {
		return fmt.Errorf("read timeout is missing")
	}
	timeoutReadDuration, err := time.ParseDuration(timeoutRead)
	if err != nil {
		return fmt.Errorf("error parsing read timeout: %w", err)
	}
	if timeoutReadDuration < 5*time.Second || timeoutReadDuration > 30*time.Minute {
		return fmt.Errorf("invalid read timeout %q, must be greater than or equal to 5 seconds and less than or equal to 30 minutes", timeoutReadDuration)
	}
	timeoutWrite := v.GetString(flagTimeoutWrite)
	if len(timeoutWrite) == 0 {
		return fmt.Errorf("write timeout is missing")
	}
	timeoutWriteDuration, err := time.ParseDuration(timeoutWrite)
	if err != nil {
		return fmt.Errorf("error parsing write timeout: %w", err)
	}
	if timeoutWriteDuration < 5*time.Second || timeoutWriteDuration > 30*time.Minute {
		return fmt.Errorf("invalid write timeout %q, must be greater than or equal to 5 seconds and less than or equal to 30 minutes", timeoutWriteDuration)
	}
	timeoutIdle := v.GetString(flagTimeoutIdle)
	if len(timeoutIdle) == 0 {
		return fmt.Errorf("idle timeout is missing")
	}
	timeoutIdleDuration, err := time.ParseDuration(timeoutIdle)
	if err != nil {
		return fmt.Errorf("error parsing idle timeout: %w", err)
	}
	if timeoutIdleDuration < 5*time.Second || timeoutIdleDuration > 30*time.Minute {
		return fmt.Errorf("invalid idle timeout %q, must be greater than or equal to 5 seconds and less than or equal to 30 minutes", timeoutIdleDuration)
	}
	if err := checkTLSConfig(v); err != nil {
		return fmt.Errorf("error with TLS configuration: %w", err)
	}
	return nil
}

func checkTLSConfig(v *viper.Viper) error {
	minVersion := v.GetString(flagTLSMinVersion)
	minVersionIndex := stringSliceIndex(SupportedTLSVersions, minVersion)
	if minVersionIndex == -1 {
		return fmt.Errorf("invalid minimum TLS version %q", minVersion)
	}
	maxVersion := v.GetString(flagTLSMaxVersion)
	maxVersionIndex := stringSliceIndex(SupportedTLSVersions, maxVersion)
	if maxVersionIndex == -1 {
		return fmt.Errorf("invalid maximum TLS version %q", maxVersion)
	}
	if minVersionIndex > maxVersionIndex {
		return fmt.Errorf("invalid TLS versions, minium version %q is greater than maximum version %q", minVersion, maxVersion)
	}
	curvePreferencesString := v.GetString(flagTLSCurvePreferences)
	if len(curvePreferencesString) == 0 {
		return fmt.Errorf("TLS curve preferences are missing")
	}
	curvePreferences := strings.Split(curvePreferencesString, ",")
	for _, curveID := range curvePreferences {
		if !stringSliceContains(SupportedCurveIDs, curveID) {
			return fmt.Errorf("invalid curve preference %q", curveID)
		}
	}
	/*
		maxVersionIndex := stringSliceContains
		if maxVersionIndex == -1 {
			return fmt.Errorf("invalid maximum TLS version %q", maxVersion)
		}
		if minVersionIndex > maxVersionIndex {
			return fmt.Errorf("invalid TLS versions, minium version %q is greater than maximum version %q", minVersion, maxVersion)
		}
	*/
	return nil
}

func checkAccessPolicyConfig(v *viper.Viper) error {
	acessPolicyFormat := v.GetString(flagAccessPolicyFormat)
	if len(acessPolicyFormat) == 0 {
		return fmt.Errorf("access policy format is missing")
	}
	acessPolicyPath := v.GetString(flagAccessPolicyPath)
	if len(acessPolicyPath) == 0 {
		return fmt.Errorf("access policy path is missing")
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

func getTLSVersion(r *http.Request) string {
	for k, v := range TLSVersionIdentifiers {
		if v == r.TLS.Version {
			return k
		}
	}
	return ""
}

func initTLSConfig(v *viper.Viper, serverKeyPair tls.Certificate, clientCAs *x509.CertPool, minVersion string, maxVersion string) *tls.Config {

	config := &tls.Config{
		Certificates: []tls.Certificate{serverKeyPair},
		ClientAuth:   tls.RequireAnyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   TLSVersionIdentifiers[minVersion],
		MaxVersion:   TLSVersionIdentifiers[maxVersion],
	}

	if tlsCurvePreferencesString := v.GetString(flagTLSCurvePreferences); len(tlsCurvePreferencesString) > 0 {
		curvePreferences := make([]tls.CurveID, 0)
		for _, str := range strings.Split(tlsCurvePreferencesString, ",") {
			curvePreferences = append(curvePreferences, TLSCurveIdentifiers[str])
		}
		config.CurvePreferences = curvePreferences
	}
	return config
}

func main() {

	rootCommand := &cobra.Command{
		Use:                   `iceberg [flags]`,
		DisableFlagsInUseLine: true,
		Short:                 "iceberg is a file server using client certificate authentication and policy-based access control.",
	}

	validateAccessPolicyCommand := &cobra.Command{
		Use:                   `validate-access-policy [--access-policy POLICY_FILE] [--access-policy-format POLICY_FORMAT]`,
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

			if errConfig := checkAccessPolicyConfig(v); errConfig != nil {
				return errConfig
			}

			accessPolicyDocument, err := policy.ParseAccessPolicy(v.GetString(flagAccessPolicyPath), v.GetString(flagAccessPolicyFormat))
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
	initFlags(validateAccessPolicyCommand.Flags())

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

			directoryListingTemplate, err := loadTemplate(v.GetString(flagTemplatePath))
			if err != nil {
				return fmt.Errorf("error loading directory listing template: %w", err)
			}

			accessPolicyDocument, err := policy.ParseAccessPolicy(v.GetString(flagAccessPolicyPath), v.GetString(flagAccessPolicyFormat))
			if err != nil {
				return fmt.Errorf("error loading policy: %w", err)
			}

			err = accessPolicyDocument.Validate()
			if err != nil {
				return fmt.Errorf("error validating policy: %w", err)
			}

			serverKeyPair, err := tls.LoadX509KeyPair(v.GetString(flagServerCert), v.GetString(flagServerKey))
			if err != nil {
				return fmt.Errorf("error loading server key pair: %w", err)
			}

			clientCAs, err := certs.LoadCertPool(v.GetString(flagClientCA), v.GetString(flagClientCAFormat))
			if err != nil {
				return fmt.Errorf("error loading client certificate authority: %w", err)
			}

			tlsMinVersion := v.GetString(flagTLSMinVersion)

			tlsMaxVersion := v.GetString(flagTLSMaxVersion)

			tlsConfig := initTLSConfig(v, serverKeyPair, clientCAs, tlsMinVersion, tlsMaxVersion)

			redirectNotFound := v.GetString(flagBehaviorNotFound) == BehaviorRedirect

			httpsServer := &http.Server{
				Addr:         listenAddress,
				IdleTimeout:  v.GetDuration(flagTimeoutIdle),
				ReadTimeout:  v.GetDuration(flagTimeoutRead),
				WriteTimeout: v.GetDuration(flagTimeoutWrite),
				TLSConfig:    tlsConfig,
				ErrorLog:     log.WrapStandardLogger(logger),
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
						"tls_version":      getTLSVersion(r),
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
							if redirectNotFound {
								http.Redirect(w, r, publicLocation, http.StatusSeeOther)
								return
							}
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
							//
							files := make([]File, 0, len(fileInfos))
							for _, fi := range fileInfos {
								fileType := "File"
								if fi.IsDir() {
									fileType = "Directory"
								}
								files = append(files, File{
									ModTime: fi.ModTime().In(time.UTC).Format(time.RFC3339),
									Size:    fi.Size(),
									Path:    filepath.Join(p, fi.Name()),
									Type:    fileType,
								})
							}
							// sort files
							sort.SliceStable(files, func(i, j int) bool {
								iType := files[i].Type
								jType := files[j].Type
								if iType != jType {
									if iType == "Directory" {
										return true
									}
									if jType == "Directory" {
										return false
									}
								}
								iStr := filepath.Base(files[i].Path)
								jStr := filepath.Base(files[j].Path)
								iValue, iErr := strconv.Atoi(iStr)
								jValue, jErr := strconv.Atoi(jStr)
								if iErr == nil && jErr == nil {
									return iValue < jValue
								}
								if iErr == nil {
									return true
								}
								if jErr == nil {
									return false
								}
								return strings.Compare(iStr, jStr) <= 0
							})
							//
							server.ServeTemplate(w, r, directoryListingTemplate, struct {
								Up        string
								Directory string
								Files     []File
							}{
								Up:        filepath.Dir(p),
								Directory: p,
								Files:     files,
							})
							return
						}
						server.ServeFile(w, r, root, indexPath, time.Time{}, false, nil)
						return
					}
					server.ServeFile(w, r, root, p, fi.ModTime(), true, nil)
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
				_ = logger.Log("Redirecting http to https", map[string]interface{}{
					"source": redirectAddress,
					"target": publicLocation,
				})
				go func() { _ = httpServer.ListenAndServe() }()
			}
			//
			_ = logger.Log("Starting server", map[string]interface{}{
				"addr":          listenAddress,
				"idleTimeout":   httpsServer.IdleTimeout.String(),
				"readTimeout":   httpsServer.ReadTimeout.String(),
				"writeTimeout":  httpsServer.WriteTimeout.String(),
				"tlsMinVersion": tlsMinVersion,
				"tlsMaxVersion": tlsMaxVersion,
			})
			return httpsServer.ListenAndServeTLS("", "")
		},
	}
	initFlags(serveCommand.Flags())

	rootCommand.AddCommand(validateAccessPolicyCommand, serveCommand)

	if err := rootCommand.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "iceberg: "+err.Error())
		_, _ = fmt.Fprintln(os.Stderr, "Try iceberg --help for more information.")
		os.Exit(1)
	}
}
