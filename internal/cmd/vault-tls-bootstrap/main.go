package vaultlogin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	vault "github.com/hashicorp/vault/api"
	"github.com/kr/pretty"
)

func init() {
	_ = pretty.Logln
}

var ErrNoVaultToken = errors.New("No vault token found in VAULT_TOKEN and could not be looked up with vault cli")

type TokenLookupResponse struct {
	Data TokenLookupResponseData `json:"data"`
}

type TokenLookupResponseData struct {
	Id         string `json:"id"`
	ExpireTime string `json:"expire_time"`
}

func findToken() (string, error) {
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		return token, nil
	}

	vaultExe, err := exec.LookPath("vault")
	if err != nil {
		log.Println("couldn't find vault executable")
		return "", err
	}

	log.Println("Found vault at", vaultExe)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel() // cancel, don't wait.

	cmd := exec.CommandContext(ctx, vaultExe, "token", "lookup", "-format=json")
	stdoutRaw, err := cmd.StdoutPipe()
	if err != nil {
		log.Println("couldn't open stdout pipe")
		return "", err
	}

	stdout := io.TeeReader(stdoutRaw, log.Writer())
	err = cmd.Start()
	if err != nil {
		log.Println("couldn't run vault cli")
		return "", err
	}

	var resp TokenLookupResponse

	if err := json.NewDecoder(stdout).Decode(&resp); err != nil {
		// reads just until it decodes the json (should be all output)
		// or it will fail.  either wait, we'll leave and cancel ctx
		log.Println("couldn't decode json")
		return "", err
	}
	log.Println("copying stdout to log")
	io.Copy(log.Writer(), stdout)

	log.Println(resp)
	return resp.Data.Id, nil
}

var ErrNoAuthMountFound = errors.New("Could not find matching auth mount")

func getAuthMountAccessor(mount string, client *vault.Client) (string, error) {
	authMounts, err := client.Sys().ListAuth()
	if err != nil {
		return "", err
	}

	for authMount, mountConfig := range authMounts {
		if authMount == mount {
			return mountConfig.Accessor, nil
		}
	}
	return "", ErrNoAuthMountFound
}

func createCubbyhole(client *vault.Client) (*vault.Client, error) {

	// NumUses is set to 6:
	// 6 - one used for a test write
	// 5 - one used for a test read
	// 4 - one used for deleting the test value
	// 3 - one used for checking num_uses left
	// --- testing done -- 2 left here
	// 2 - one used to write the final secret
	// --- writing done -- ready to send to final destination
	// 1 - one used to read the secret and invalidate the cubbyhole
	tokSecret, err := client.Auth().Token().CreateOrphan(&vault.TokenCreateRequest{
		Policies:  []string{"default"},
		TTL:       "5m",
		Renewable: new(bool),
		NumUses:   6,
	})
	if err != nil {
		log.Println("could not create cubbyhole token", err)
		return nil, err
	}

	tok, err := tokSecret.TokenID()
	if err != nil {
		log.Println("Could not extract token from secret:", tokSecret, err)
		return nil, err
	}

	cubby, err := vault.NewClient(client.CloneConfig())
	if err != nil {
		log.Println("could not create a new cubbyhole client", err)
		return nil, err
	}
	cubby.SetToken(tok)

	err = testCubbyholeAccess(cubby)
	if err != nil {
		return nil, err
	}
	return cubby, nil
}

var ErrCubbyholeTestNotMatched = errors.New("secret read did not match secret written during cubbyhole test")
var ErrCubbyholeTestWrongNumUsesLeft = errors.New("wrong number of num_uses left after testing (should be 2 left)")

func testCubbyholeAccess(client *vault.Client) error {
	tv := uuid.New().String()
	_, err := client.Logical().Write("cubbyhole/test", map[string]interface{}{
		"x": tv,
	})
	if err != nil {
		log.Println("Could not set cubbyhole/test")
		return err
	}
	log.Println("writing test value to cubbyhole/test", tv)
	secret, err := client.Logical().Read("cubbyhole/test")
	if err != nil {
		log.Println("Could not read cubbyhole/test")
		return err
	}
	if secret.Data["x"] != tv {
		return ErrCubbyholeTestNotMatched
	}
	log.Println("read test value from cubbyhole/test", secret.Data["x"])
	_, err = client.Logical().Delete("cubbyhole/test")
	if err != nil {
		log.Println("Could not delete cubbyhole/test after test write/read")
		return err
	}

	tokenInfo, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return err
	}
	if v, ok := tokenInfo.Data["num_uses"].(json.Number); !ok || v.String() != "2" {
		if !ok {
			pretty.Logln("Could not find num_uses")
		}
		pretty.Logln("wrong num_uses left or num_uses not found", tokenInfo.Data)
		return ErrCubbyholeTestWrongNumUsesLeft
	} else {
		log.Println("Token has", v.String(), "uses left (the best uses left)")
	}
	return nil
}

//func createConsulClientPKI(client *vault.Client) {
//}

var (
	ttl                    string
	altNames               []string
	vaultAddr              string
	consulNodeSubdomain    string
	pkiSecretMount         string
	pkiSecretRole          string
	pkiSecretSudoRole      string
	consulHttpAddr         string
	vaultConsulSecretPath  string
	vaultConsulManagerRole string
	baseName               string
	commonName             string
	flagSet                *flag.FlagSet
	consulTld              string
	consulDatacenter       string
)

func init() {
	flagSet = flag.NewFlagSet("Vault TLS Bootstrapper", flag.ExitOnError)
	ttl = "3h"
	vaultAddr = "https://vault.service.consul:8200"
	flagSet.StringVar(&vaultAddr, "vault-addr", vaultAddr, `https url for vault (_must_ be https)`)
	consulNodeSubdomain = "node.dc1.consul"
	flagSet.StringVar(&consulNodeSubdomain, "consul-node-subdomain", consulNodeSubdomain, "consul subdomain where individual nodes are found")
	flagSet.StringVar(&consulTld, "consul-tld", "consul", "TLD for dns lookups in consul")
	flagSet.StringVar(&consulDatacenter, "consul-dc", "dc1", "datacenter in consul where this host will be registered")
	flagSet.Func("alt-name", "SAN domain name to add to cert (may be repeated)", func(s string) error {
		altNames = append(altNames, s)
		return nil
	})
	pkiSecretMount = "consul_pki"
	pkiSecretRole = "consul-client"
	pkiSecretSudoRole = pkiSecretRole + "-sudo"
	consulHttpAddr = "https://consul.service.consul:8501"
	vaultConsulSecretPath = "consul"
	vaultConsulManagerRole = "manager"
}

func issueCert(client *vault.Client, mount, role, commonName string, altNames []string, ttl string) (*vault.Secret, error) {
	read, err := client.Logical().Write(mount+"/issue/"+role, map[string]interface{}{
		"common_name": commonName,
		"ttl":         ttl,
		"alt_names":   strings.Join(altNames, ","),
	})
	if err != nil {
		pretty.Logln("couldn't generate a cert", err)
		return nil, err
	}
	return read, nil
}

type certAuthHandler struct {
	mount string
}

func (cah certAuthHandler) Login(ctx context.Context, client *vault.Client) (*vault.Secret, error) {
	log.Println("Authing")
	secret, err := client.Logical().Write("auth/"+strings.TrimSuffix(cah.mount, "/")+"/login", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	pretty.Logln(secret)
	return secret, nil
}

func vaultCertClient(config *vault.Config, authMount string, secret *vault.Secret) (*vault.Client, error) {
	cert, err := tls.X509KeyPair([]byte(secret.Data["certificate"].(string)), []byte(secret.Data["private_key"].(string)))

	t := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	httpClient := http.Client{Transport: t, Timeout: 15 * time.Second}
	config.HttpClient = &httpClient

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}
	cah := certAuthHandler{authMount}

	_, err = client.Auth().Login(context.Background(), cah)
	if err != nil {
		log.Println("Couldn't login with cert auth", err)
		return nil, err
	}
	return client, nil
}

func RunCLI(args []string) int {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if err := flagSet.Parse(args[1:]); err != nil {
		log.Fatalln("couldn't parse args", err)
	}

	altNames = append(altNames, "client."+consulDatacenter+"."+consulTld)

	baseName = flagSet.Arg(0)
	commonName = baseName + "." + consulNodeSubdomain

	config := vault.DefaultConfig()

	config.Address = vaultAddr

	client, err := vault.NewClient(config)
	if err != nil {
		log.Fatalf("unable to initialize Vault client: %v", err)
	}
	token, err := findToken()
	if err != nil {
		log.Fatalln("could not find a token to use", err)
	}
	client.SetToken(token)

	log.Println(client.Auth().Token().RenewSelf(0))

	getAuthMountAccessor("cert/", client)

	cubby, err := createCubbyhole(client)
	if err != nil {
		log.Fatalln("could not create cubbyhole client", err)
	}
	_ = cubby

	cert, err := issueCert(client, pkiSecretMount, pkiSecretSudoRole, commonName, altNames, "5m")
	if err != nil {
		log.Fatalln(err)
	}
	certClient, err := vaultCertClient(client.CloneConfig(), "cert", cert)
	if err != nil {
		log.Fatalln(err)
	}
	cert2, err := issueCert(certClient, pkiSecretMount, pkiSecretRole, commonName, altNames, "5m")
	if err != nil {
		log.Fatalln(err)
	}
	cert2Client, err := vaultCertClient(client.CloneConfig(), "cert", cert2)
	if err != nil {
		log.Fatalln(err)
	}
	cert3, err := issueCert(cert2Client, pkiSecretMount, pkiSecretRole, commonName, altNames, "72h")
	if err != nil {
		log.Fatalln(err)
	}

	_, err = cubby.Logical().Write("cubbyhole/cert", cert3.Data)
	if err != nil {
		log.Fatalln("Could not set cubbyhole/cert", err)
	}

	log.Println("Cubby token:", cubby.Token())
	return 0
}
