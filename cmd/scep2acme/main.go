package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/providers/dns"
	"github.com/go-acme/lego/v3/registration"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/micromdm/scep/crypto/x509util"
	"github.com/micromdm/scep/csrverifier"
	"github.com/micromdm/scep/scep"
	"github.com/micromdm/scep/server"
	"go.bog.dev/errpool"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
)

var (
	listenPort    = flag.String("listen", "127.0.0.1:8383", "Listen IP and port")
	certPath      = flag.String("cert", "", "Path to certificate file - should include 2 certificates (RA & CA). RA certificate should be signed by CA.")
	certKeyPath   = flag.String("certkey", "", "Path to certificate key")
	acmeKeyPath   = flag.String("acmekey", "", "Path to ACME account key")
	acmeEmail     = flag.String("acmeemail", "", "ACME account email address - Terms of Service will be accepted automatically")
	acmeUrl       = flag.String("acmeurl", lego.LEDirectoryStaging, fmt.Sprintf("ACME directory URL (default is the Let's Encrypt staging directory, to switch to production directory use \"%v\")", lego.LEDirectoryProduction))
	whitelistPath = flag.String("whitelist", "", "Path to hostname whitelist configuration")
	dnsProvider   = flag.String("dnsprovider", "", "DNS provider used for DNS-01 challenges - environment variables should be used for configuration, docs at https://go-acme.github.io/lego/dns/")
	debug         = flag.Bool("debug", false, "Enable debug logging")
)

type serviceWithoutRenewal struct {
	scepserver.Service
}

func (s serviceWithoutRenewal) GetCACaps(ctx context.Context) ([]byte, error) {
	capsBytes, err := s.Service.GetCACaps(ctx)
	if err != nil {
		return nil, err
	}

	newCaps := strings.ReplaceAll(" "+string(capsBytes)+" ", "\nRenewal\n", "\n")
	return []byte(newCaps[1 : len(newCaps)-1]), nil
}

type myDepot struct{}

func (d *myDepot) CA(pass []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	caPEM, err := ioutil.ReadFile(*certPath)
	if err != nil {
		return nil, nil, err
	}
	certs, err := d.loadCerts(caPEM)
	if err != nil {
		return nil, nil, err
	}

	keyPEM, err := ioutil.ReadFile(*certKeyPath)
	if err != nil {
		return nil, nil, err
	}
	key, err := d.loadKey(keyPEM, nil)
	if err != nil {
		return nil, nil, err
	}

	return certs, key, nil
}

func (d *myDepot) loadKey(data []byte, password []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, fmt.Errorf("PEM decode failed")
	}

	if pemBlock.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	} else {
		ret, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		return ret.(*rsa.PrivateKey), err
	}
}

func (d *myDepot) loadCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for {
		var pemBlock *pem.Block
		pemBlock, data = pem.Decode(data)
		if pemBlock == nil {
			if len(certs) == 0 {
				return nil, fmt.Errorf("PEM decode failed")
			} else {
				break
			}
		}

		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing cert %v: %w", len(certs), err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func (d *myDepot) Serial() (*big.Int, error) {
	return nil, fmt.Errorf("myDepot cannot create certificates")
}

func (d *myDepot) HasCN(cn string, allowTime int, cert *x509.Certificate, revokeOldCertificate bool) (bool, error) {
	// TODO: does this matter?
	return false, nil
}

func (d *myDepot) Put(name string, crt *x509.Certificate) error {
	return nil
}

type acmeUserInfo struct {
	registration *registration.Resource
}

func (u *acmeUserInfo) GetEmail() string {
	return *acmeEmail
}

func (u *acmeUserInfo) GetRegistration() *registration.Resource {
	return u.registration
}

func (u *acmeUserInfo) GetPrivateKey() crypto.PrivateKey {
	data, err := ioutil.ReadFile(*acmeKeyPath)
	if err != nil {
		panic(err)
	}

	keyData, data := pem.Decode(data)

	key, err := x509.ParsePKCS1PrivateKey(keyData.Bytes)
	if err != nil {
		panic(err)
	}

	return key
}

func acmeCreateCertificate(client *lego.Client) scepserver.CertificateSource {
	return scepserver.CertificateSourceFunc(func(ctx context.Context, msg *scep.PKIMessage) (*x509.Certificate, error) {
		res, err := client.Certificate.ObtainForCSR(*msg.CSR, false)
		if err != nil {
			return nil, fmt.Errorf("ObtainForCSR: %w", err)
		}

		certBytes, _ := pem.Decode(res.Certificate)
		crt, err := x509.ParseCertificate(certBytes.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing obtained cert: %w", err)
		}

		return crt, nil
	})
}

type hostnameMatcher func(hostname string) bool

type csrPasswordVerifier struct {
	passwordMatchers map[string][]hostnameMatcher
}

func (c *csrPasswordVerifier) allowedDnsName(password string, dnsName string) bool {
	for _, matcher := range c.passwordMatchers[password] {
		if matcher(dnsName) {
			return true
		}
	}
	return false
}

func (c *csrPasswordVerifier) Verify(data []byte) (bool, error) {
	cp, err := x509util.ParseChallengePassword(data)
	if err != nil {
		return false, fmt.Errorf("scep: parse challenge password in pkiEnvelope: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(data)
	if err != nil {
		return false, err
	}

	if !c.allowedDnsName(cp, csr.Subject.CommonName) {
		fmt.Printf("Subject CN not allowed: %v\n", csr.Subject.CommonName)
		return false, nil
	}

	for _, name := range csr.DNSNames {
		if !c.allowedDnsName(cp, name) {
			fmt.Printf("SAN not allowed: %v\n", name)
			return false, nil
		}
	}

	fmt.Printf("CSR passed verification: %+v\n", csr)

	return true, nil
}

func hostnameExactMatcher(name string) func(string) bool {
	return func(hostname string) bool {
		return name == hostname
	}
}

func newCsrPasswordVerifier(yamlPath string) (csrverifier.CSRVerifier, error) {
	data, err := ioutil.ReadFile(yamlPath)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var mapping map[string]interface{}
	err = yaml.Unmarshal(data, &mapping)
	if err != nil {
		return nil, fmt.Errorf("parsing file: %w", err)
	}

	c := &csrPasswordVerifier{
		passwordMatchers: map[string][]hostnameMatcher{},
	}

	for pass, value := range mapping {
		items := []interface{}{value}

		if v, ok := value.([]interface{}); ok {
			items = v
		}

		for _, item := range items {
			switch item.(type) {
			case string:
				c.passwordMatchers[pass] = append(c.passwordMatchers[pass], hostnameExactMatcher(item.(string)))
			default:
				return nil, fmt.Errorf("unknown item: %v (type %v)", item, reflect.TypeOf(item))
			}
		}
	}

	return c, nil
}

func setupAcmeClient() (*lego.Client, error) {
	acmeUser := &acmeUserInfo{}
	acmeConfig := lego.NewConfig(acmeUser)
	acmeConfig.CADirURL = *acmeUrl

	client, err := lego.NewClient(acmeConfig)
	if err != nil {
		return nil, fmt.Errorf("creating acme client: %w", err)
	}

	provider, err := dns.NewDNSChallengeProviderByName(*dnsProvider)
	if err != nil {
		return nil, fmt.Errorf("creating challenge provider: %w", err)
	}

	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		return nil, fmt.Errorf("setting challenge provider: %w", err)
	}

	acmeUser.registration, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("registering acme account: %w", err)
	}

	return client, nil
}

func mandatoryFlag(name string, value interface{}) {
	if reflect.Indirect(reflect.ValueOf(value)).IsZero() {
		panic(fmt.Sprintf("-%v is mandatory, use -help for help", name))
	}
}

func main() {
	flag.Parse()

	mandatoryFlag("cert", certPath)
	mandatoryFlag("certkey", certKeyPath)
	mandatoryFlag("acmeemail", acmeKeyPath)
	mandatoryFlag("acmekey", acmeKeyPath)
	mandatoryFlag("dnsprovider", acmeKeyPath)
	mandatoryFlag("whitelist", whitelistPath)

	client, err := setupAcmeClient()
	if err != nil {
		panic(err)
	}

	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stderr)
		if !*debug {
			logger = level.NewFilter(logger, level.AllowInfo())
		}
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
	}
	lginfo := level.Info(logger)

	verifier, err := newCsrPasswordVerifier(*whitelistPath)
	if err != nil {
		panic(fmt.Errorf("loading whitelist: %w", err))
	}

	var svc scepserver.Service
	{
		svcOptions := []scepserver.ServiceOption{
			scepserver.WithLogger(logger),
			scepserver.WithCSRVerifier(verifier),
			scepserver.WithCertificateSource(acmeCreateCertificate(client)),
		}
		svc, err = scepserver.NewService(&myDepot{}, svcOptions...)
		if err != nil {
			panic(err)
		}
		svc = serviceWithoutRenewal{svc}
		svc = scepserver.NewLoggingService(log.With(lginfo, "component", "scep_service"), svc)
	}

	var h http.Handler
	{
		e := scepserver.MakeServerEndpoints(svc)
		e.GetEndpoint = scepserver.EndpointLoggingMiddleware(lginfo)(e.GetEndpoint)
		e.PostEndpoint = scepserver.EndpointLoggingMiddleware(lginfo)(e.PostEndpoint)
		h = scepserver.MakeHTTPHandler(e, svc, log.With(lginfo, "component", "http"))
	}

	pool := errpool.Unbounded(context.Background())

	server := http.Server{
		Addr:    *listenPort,
		Handler: h,
	}
	pool.Go(func(ctx context.Context) error {
		return server.ListenAndServe()
	})
	pool.Go(func(ctx context.Context) error {
		<-ctx.Done()
		return server.Shutdown(context.Background())
	})

	pool.Go(func(ctx context.Context) error {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGTERM)
		return fmt.Errorf("%v", <-c)
	})

	lginfo.Log("terminated", pool.Wait())
}
