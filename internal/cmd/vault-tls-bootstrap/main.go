package vaultlogin

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	consul "github.com/hashicorp/consul/api"
	vault "github.com/hashicorp/vault/api"
	"github.com/jamesandariese/hashistack-node-bootstrapper/version"
	"github.com/rs/zerolog"
)

var ErrNoVaultToken = errors.New("No vault token found in VAULT_TOKEN and could not be looked up with vault cli")

type TokenLookupResponse struct {
	Data TokenLookupResponseData `json:"data"`
}

type TokenLookupResponseData struct {
	Id         string `json:"id"`
	ExpireTime string `json:"expire_time"`
}

type Program struct {
	logger                 zerolog.Logger
	ttl                    string
	altNames               []string
	vaultAddr              string
	certAuthMount          string
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
	versionRequested       bool
	vaultEntityName        string
	vaultEntityId          string
}

func NewZerologLevelledWriter(l zerolog.Logger, v zerolog.Level) io.Writer {
	r, pw := io.Pipe()
	s := bufio.NewScanner(r)
	go func() {
		for s.Scan() {
			l.WithLevel(v).Msg(s.Text())
		}
		r.Close()
		pw.Close()
	}()
	return pw
}

func NewProgram() (*Program, *flag.FlagSet) {
	p := &Program{}

	p.flagSet = flag.NewFlagSet("Vault TLS Bootstrapper", flag.ContinueOnError)
	p.flagSet.BoolVar(&p.versionRequested, "version", false, "print version and exit")
	p.ttl = "3h"
	vaultAddr := "https://vault.service.consul:8200"
	p.flagSet.StringVar(&p.vaultAddr, "vault-addr", vaultAddr, `https url for vault (_must_ be https)`)
	p.flagSet.StringVar(&p.consulTld, "consul-tld", "consul", "TLD for dns lookups in consul")
	p.flagSet.StringVar(&p.consulDatacenter, "consul-dc", "dc1", "datacenter in consul where this host will be registered")
	p.certAuthMount = "cert"
	p.flagSet.Func("cert-auth-mount", "auth mount for generated cert to auth against", func(s string) error {
		p.certAuthMount = strings.TrimSuffix(s, "/")
		return nil
	})
	p.flagSet.Func("alt-name", "SAN domain name to add to cert (may be repeated)", func(s string) error {
		p.altNames = append(p.altNames, s)
		return nil
	})
	p.flagSet.StringVar(&p.pkiSecretMount, "vault-pki-mount", "consul_pki", "vault pki secret mount for consul certificate generation")
	p.flagSet.StringVar(&p.pkiSecretRole, "vault-pki-role", "consul-client", "vault role in pki mount which may create certificates for its own nodename")
	p.flagSet.StringVar(&p.pkiSecretSudoRole, "vault-pki-sudo-role", "consul-client-sudo", "vault role in pki mount which may create certificates for other hosts")
	p.flagSet.StringVar(&p.consulHttpAddr, "consul-addr", "https://consul.service.consul:8501", "address of consul API")
	p.flagSet.StringVar(&p.vaultConsulSecretPath, "vault-consul-secret-path", "consul", "FIXME")
	p.flagSet.StringVar(&p.vaultConsulManagerRole, "vault-consul-manager-role", "manager", "FIXME")
	return p, p.flagSet
}

func (my *Program) SetLogger(l zerolog.Logger) *Program {
	my.logger = l
	return my
}

func (my *Program) findToken() (string, error) {
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		return token, nil
	}

	vaultExe, err := exec.LookPath("vault")
	if err != nil {
		my.logger.Print("couldn't find vault executable")
		return "", err
	}

	my.logger.Print("Found vault at " + vaultExe)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, vaultExe, "token", "lookup", "-format=json")
	stdoutRaw, err := cmd.StdoutPipe()
	if err != nil {
		my.logger.Print("couldn't open stdout pipe")
		return "", err
	}

	my.logger.Print("copying vault token lookup stdout to log")
	nlw := NewZerologLevelledWriter(my.logger, zerolog.TraceLevel)
	stdout := io.TeeReader(stdoutRaw, nlw)
	err = cmd.Start()
	if err != nil {
		my.logger.Print("couldn't run vault cli")
		return "", err
	}

	var resp TokenLookupResponse

	if err := json.NewDecoder(stdout).Decode(&resp); err != nil {
		// reads just until it decodes the json (should be all output)
		// or it will fail.  either wait, we'll leave and cancel ctx
		my.logger.Print("couldn't decode json")
		return "", err
	}
	cmd.Wait()
	my.logger.Trace().Msgf("%#v", resp)
	return resp.Data.Id, nil
}

var ErrNoAuthMountFound = errors.New("Could not find matching auth mount")

func getAuthMountAccessor(mount string, client *vault.Client) (string, error) {
	mount = strings.TrimSuffix(mount, "/") + "/"
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

func (my *Program) createCubbyhole(client *vault.Client) (*vault.Client, error) {

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
		my.logger.Error().Err(err).Msg("could not create cubbyhole token")
		return nil, err
	}

	tok, err := tokSecret.TokenID()
	if err != nil {
		my.logger.Error().Err(err).Msg("Could not extract token from secret")
		return nil, err
	}

	cubby, err := vault.NewClient(client.CloneConfig())
	if err != nil {
		my.logger.Error().Err(err).Msg("could not create a new cubbyhole client")
		return nil, err
	}
	cubby.SetToken(tok)

	err = my.testCubbyholeAccess(cubby)
	if err != nil {
		my.logger.Error().Err(err).Msg("Cubbyhole access test failed")
		return nil, err
	}
	return cubby, nil
}

var ErrCubbyholeTestNotMatched = errors.New("secret read did not match secret written during cubbyhole test")
var ErrCubbyholeTestWrongNumUsesLeft = errors.New("wrong number of num_uses left after testing (should be 2 left)")

func (my *Program) testCubbyholeAccess(client *vault.Client) error {
	tv := uuid.New().String()
	_, err := client.Logical().Write("cubbyhole/test", map[string]interface{}{
		"x": tv,
	})
	if err != nil {
		my.logger.Print("Could not set cubbyhole/test")
		return err
	}
	my.logger.Print("writing test value to cubbyhole/test " + tv)
	secret, err := client.Logical().Read("cubbyhole/test")
	if err != nil {
		my.logger.Print("Could not read cubbyhole/test")
		return err
	}

	secretX, ok := secret.Data["x"].(string)
	if !ok {
		my.logger.Print("secret Data[\"x\"] is not a string")
		return ErrCubbyholeTestNotMatched
	}
	if secret.Data["x"] != tv {
		return ErrCubbyholeTestNotMatched
	}
	my.logger.Print("read test value from cubbyhole/test " + secretX)
	_, err = client.Logical().Delete("cubbyhole/test")
	if err != nil {
		my.logger.Print("Could not delete cubbyhole/test after test write/read")
		return err
	}

	tokenInfo, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return err
	}
	if v, ok := tokenInfo.Data["num_uses"].(json.Number); !ok || v.String() != "2" {
		if !ok {
			my.logger.Print("Could not find num_uses")
		}
		my.logger.Print("wrong num_uses left or num_uses not found" + v)
		return ErrCubbyholeTestWrongNumUsesLeft
	} else {
		my.logger.Print("Token has " + v.String() + " uses left (the best uses left)")
	}
	return nil
}

//func createConsulClientPKI(client *vault.Client) {
//}

func (my *Program) issueCert(client *vault.Client, mount, role, commonName string, altNames []string, ttl string) (*vault.Secret, error) {
	read, err := client.Logical().Write(mount+"/issue/"+role, map[string]interface{}{
		"common_name": commonName,
		"ttl":         ttl,
		"alt_names":   strings.Join(altNames, ","),
	})
	if err != nil {
		my.logger.Error().Err(err).Msg("couldn't generate a cert")
		return nil, err
	}
	return read, nil
}

type certAuthHandler struct {
	p     *Program
	mount string
}

func (cah certAuthHandler) Login(ctx context.Context, client *vault.Client) (*vault.Secret, error) {
	cah.p.logger.Print("Authing")
	secret, err := client.Logical().Write("auth/"+strings.TrimSuffix(cah.mount, "/")+"/login", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	cah.p.logger.Trace().Msgf("%#v", secret)
	return secret, nil
}

func (my *Program) vaultCertClient(config *vault.Config, authMount string, secret *vault.Secret) (*vault.Client, error) {
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
	cah := certAuthHandler{my, authMount}

	_, err = client.Auth().Login(context.Background(), cah)
	if err != nil {
		my.logger.Error().Err(err).Msg("Couldn't login with cert auth")
		return nil, err
	}
	return client, nil
}

var ErrConsulCredsFormatError = errors.New("consul creds not found in .Data[\"token\"]")

func (my *Program) consulLoginFromVault(vault *vault.Client, consulConfig *consul.Config, consulSecretPath, consulManagerRole string) (*consul.Client, error) {
	p := consulSecretPath + "/creds/" + consulManagerRole
	consulCreds, err := vault.Logical().Read(p)
	if err != nil {
		my.logger.Error().Err(err).Msg("Couldn't read consul secret for manager role at: " + p)
		return nil, err
	}
	token, ok := consulCreds.Data["token"].(string)
	if !ok {
		return nil, ErrConsulCredsFormatError
	}
	consulConfig.Token = token
	client, err := consul.NewClient(consulConfig)
	if err != nil {
		my.logger.Error().Err(err).Msg("failed to create a consul client")
		return nil, err
	}

	policy, _, err := client.ACL().PolicyRead("00000000-0000-0000-0000-000000000001", nil)
	if err != nil {
		my.logger.Error().Err(err).Msg("failed to lookup management policy when testing consul creds")
		return nil, err
	}

	my.logger.Debug().Msg("looked up management policy to test. got: " + policy.Name)

	return client, nil
}

var ErrEntityIdNotFound = errors.New("entity id did not contain \"id\" at .Data[\"id\"]")

func (my *Program) linkConsulIdentity(vaultClient *vault.Client, consulClient *consul.Client, certMountAccessor, baseName, commonName string) error {
	// find the vault entity id for commonName in certMountAccessor
	// set entity name for entity id to commonName (for easily finding with human eyeballs)
	// create a consul policy named node__{{baseName}} (if it doesn't exist)
	// add policy for node "{{baseName}}" with kv node/{{baseName}}
	// create a vault consul secret path role for the consul policy node__{{baseName}} which confers node__{{baseName}} policies
	// give access to read creds from consul/roles/node__{{baseName}} to consul-secret-reader-node__{{baseName}}
	// give the vault entity access to the policy consul-secret-reader-node__{{baseName}}

	vl := vaultClient.Logical()
	vs := vaultClient.Sys()

	entityIdResult, err := vl.Write("identity/lookup/entity", map[string]interface{}{
		"alias_name":           commonName,
		"alias_mount_accessor": certMountAccessor,
	})
	if err != nil {
		my.logger.Error().Err(err).Msg("couldn't lookup entity at identity/lookup/entity")
		return err
	}
	entityId, ok := entityIdResult.Data["id"].(string)
	if !ok {
		return ErrEntityIdNotFound
	}

	_, err = vl.Write("identity/entity/id/"+entityId, map[string]interface{}{
		"name": commonName,
	})
	if err != nil {
		my.logger.Error().Err(err).Msg("failed to set entity name")
		return err
	}

	my.vaultEntityId = entityId
	my.vaultEntityName = commonName

	consulPolicyName := "node__" + baseName
	aclClient := consulClient.ACL()

	addRulesToPolicy := func(policy *consul.ACLPolicy) *consul.ACLPolicy {
		if policy == nil {
			policy = &consul.ACLPolicy{
				Name:        consulPolicyName,
				Description: "policy for hashistack client " + baseName,
			}
		}
		policy.Rules = `
			node "` + baseName + `" {
				policy = "write"
			}
			node_prefix "" {
				policy = "read"
			}
			service_prefix "" {
				policy = "read"
			}
			query_prefix "" {
				policy = "read"
			}
			key_prefix "node/` + baseName + `/" {
				policy = "write"
			}
		`
		return policy
	}

	policy, _, err := aclClient.PolicyReadByName(consulPolicyName, nil)
	if err != nil {
		my.logger.Debug().Err(err).Msgf("error looking up policy %s.  continuing anyway since it may simply not exist.", consulPolicyName)
	}
	if policy == nil {
		my.logger.Debug().Msg("No existing policy named " + consulPolicyName + " found.  Creating a new one.")
		_, _, err = aclClient.PolicyCreate(addRulesToPolicy(nil), nil)
		if err != nil {
			my.logger.Error().Err(err).Msg("Couldn't create policy")
			return err
		}
	} else {
		my.logger.Print("Found existing policy named " + consulPolicyName + " updating.")
		_, _, err = aclClient.PolicyUpdate(addRulesToPolicy(policy), nil)
		if err != nil {
			my.logger.Error().Err(err).Msg("Couldn't update policy")
			return err
		}
	}

	_, err = vl.Write("consul/roles/"+consulPolicyName, map[string]interface{}{
		"policies": consulPolicyName,
	})
	if err != nil {
		my.logger.Error().Err(err).Msg("Couldn't create/update role in consul mount named " + consulPolicyName)
		return err
	}

	vaultPolicy := `
		path "consul/creds/` + consulPolicyName + `" {
			capabilities = ["read"]
		}
	`
	secretReader := "consul-secret-reader-" + consulPolicyName
	err = vs.PutPolicy(secretReader, vaultPolicy)
	if err != nil {
		my.logger.Error().Err(err).Msg("couldn't write to policy named consul-secret-reader-" + consulPolicyName)
		return err
	}
	_, err = vl.Write("identity/entity/id/"+entityId, map[string]interface{}{
		"policies": secretReader,
	})

	if err != nil {
		my.logger.Error().Err(err).Msg("couldn't create/update identity/entity/id/" + entityId + " with policy " + secretReader)
		return err
	}

	return nil
}

const (
	errnoSuccess = iota
	errnoBadFlags
	errnoHelp
	errnoInitVaultClient
	errnoFindVaultToken
	errnoConsulLogin
	errnoMountAccessor
	errnoCubbyholeClient
	errnoIssueCert1
	errnoVaultLoginCert1
	errnoIssueCert2
	errnoVaultLoginCert2
	errnoIssueCert3
	errnoCubbyholeWrite
	errnoLinkConsulIdentity
)

func (my *Program) RunCLI() int {
	if my.versionRequested {
		fmt.Println(version.Version)
		return 0
	}
	my.altNames = append(my.altNames, "client."+my.consulDatacenter+"."+my.consulTld)

	my.baseName = my.flagSet.Arg(0)

	if my.baseName == "" {
		my.flagSet.Usage()
		return 14
	}

	my.commonName = strings.Join([]string{my.baseName, "node", my.consulDatacenter, my.consulTld}, ".")

	// login to vault with whatever creds we already have (from vault login, usually)
	config := vault.DefaultConfig()

	config.Address = my.vaultAddr

	client, err := vault.NewClient(config)
	if err != nil {
		my.logger.Error().Err(err).Msg("unable to initialize Vault client")
		return errnoInitVaultClient
	}
	token, err := my.findToken()
	if err != nil {
		my.logger.Error().Err(err).Msg("could not find a token to use")
		return errnoFindVaultToken
	}
	client.SetToken(token)

	_, err = client.Auth().Token().RenewSelf(0)
	if err != nil {
		my.logger.Error().Err(err).Msg("Unable to renew token.  Continuing anyway.")
	}
	// done logging into vault

	// login to consul with creds from vault
	consulConfig := consul.DefaultConfig()

	consulClient, err := my.consulLoginFromVault(client, consulConfig, my.vaultConsulSecretPath, my.vaultConsulManagerRole)
	if err != nil {
		my.logger.Error().Err(err).Msg("Failed to login to consul via vault")
		return errnoConsulLogin
	}

	certAccessor, err := getAuthMountAccessor(my.certAuthMount, client)
	if err != nil {
		my.logger.Error().Err(err).Msg("could not find mount accessor")
		return errnoMountAccessor
	}
	_ = certAccessor

	cubby, err := my.createCubbyhole(client)
	if err != nil {
		my.logger.Error().Err(err).Msg("could not create cubbyhole client")
		return errnoCubbyholeClient
	}
	_ = cubby

	cert, err := my.issueCert(client, my.pkiSecretMount, my.pkiSecretSudoRole, my.commonName, my.altNames, "5m")
	if err != nil {
		my.logger.Print(err)
		return errnoIssueCert1
	}
	certClient, err := my.vaultCertClient(client.CloneConfig(), my.certAuthMount, cert)
	if err != nil {
		my.logger.Print(err)
		return errnoVaultLoginCert1
	}
	cert2, err := my.issueCert(certClient, my.pkiSecretMount, my.pkiSecretRole, my.commonName, my.altNames, "5m")
	if err != nil {
		my.logger.Print(err)
		return errnoIssueCert2
	}
	cert2Client, err := my.vaultCertClient(client.CloneConfig(), my.certAuthMount, cert2)
	if err != nil {
		my.logger.Print(err)
		return errnoVaultLoginCert2
	}
	cert3, err := my.issueCert(cert2Client, my.pkiSecretMount, my.pkiSecretRole, my.commonName, my.altNames, "72h")
	if err != nil {
		my.logger.Print(err)
		return errnoIssueCert3
	}

	_, err = cubby.Logical().Write("cubbyhole/cert", cert3.Data)
	if err != nil {
		my.logger.Error().Err(err).Msg("Could not set cubbyhole/cert")
		return errnoCubbyholeWrite
	}

	err = my.linkConsulIdentity(client, consulClient, certAccessor, my.baseName, my.commonName)
	if err != nil {
		my.logger.Print("Could not create consul identity")
		return errnoLinkConsulIdentity
	}

	my.logger.Info().Msgf("Certificate login is associated with the following identity entity: %s", my.vaultEntityName)
	my.logger.Info().Msgf("You may edit it at %s/ui/vault/access/identity/entities/%s/details", my.vaultAddr, my.vaultEntityId)

	my.logger.Info().Msgf("Cubbyhole token may be used to recover the generated certificate.  You may do so only once.")
	my.logger.Info().Msgf("If you receive a permission denied error within the TTL, investigate possible token theft.")
	my.logger.Info().Msgf("Run the following command to retrieve the token (assumes vault is properly configured):")

	my.logger.Info().Msgf("VAULT_TOKEN=%s vault read cubbyhole/cert", cubby.Token())
	my.logger.Info().Msgf("--- or to make the artifacts available as env vars ($CONSUL_CERT $CONSUL_KEY $CONSUL_CA) (requires jq) ---")
	jqDisassemblerString := `.data| @sh "CONSUL_CERT=\(.certificate)", @sh "CONSUL_KEY=\(.private_key)", @sh "CONSUL_CA=\(.ca_chain)"`
	my.logger.Info().Msgf(`eval "$(VAULT_TOKEN=%q vault read -format=json cubbyhole/cert|jq -r %q)"`, cubby.Token(), jqDisassemblerString)
	my.logger.Info().Msg("Cubby token: " + cubby.Token())
	fmt.Println(cubby.Token())
	return 0
}
