package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"net/mail"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/arthurweinmann/go-https-hug/pkg/storage"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/allinkl"
	"github.com/go-acme/lego/v4/providers/dns/arvancloud"
	"github.com/go-acme/lego/v4/providers/dns/auroradns"
	"github.com/go-acme/lego/v4/providers/dns/autodns"
	"github.com/go-acme/lego/v4/providers/dns/azure"
	"github.com/go-acme/lego/v4/providers/dns/bindman"
	"github.com/go-acme/lego/v4/providers/dns/bluecat"
	"github.com/go-acme/lego/v4/providers/dns/brandit"
	"github.com/go-acme/lego/v4/providers/dns/bunny"
	"github.com/go-acme/lego/v4/providers/dns/checkdomain"
	"github.com/go-acme/lego/v4/providers/dns/civo"
	"github.com/go-acme/lego/v4/providers/dns/clouddns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/cloudns"
	"github.com/go-acme/lego/v4/providers/dns/cloudxns"
	"github.com/go-acme/lego/v4/providers/dns/conoha"
	"github.com/go-acme/lego/v4/providers/dns/constellix"
	"github.com/go-acme/lego/v4/providers/dns/derak"
	"github.com/go-acme/lego/v4/providers/dns/desec"
	"github.com/go-acme/lego/v4/providers/dns/designate"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/providers/dns/dnshomede"
	"github.com/go-acme/lego/v4/providers/dns/dnsimple"
	"github.com/go-acme/lego/v4/providers/dns/dnsmadeeasy"
	"github.com/go-acme/lego/v4/providers/dns/dnspod"
	"github.com/go-acme/lego/v4/providers/dns/dode"
	"github.com/go-acme/lego/v4/providers/dns/domeneshop"
	"github.com/go-acme/lego/v4/providers/dns/dreamhost"
	"github.com/go-acme/lego/v4/providers/dns/duckdns"
	"github.com/go-acme/lego/v4/providers/dns/dyn"
	"github.com/go-acme/lego/v4/providers/dns/dynu"
	"github.com/go-acme/lego/v4/providers/dns/easydns"
	"github.com/go-acme/lego/v4/providers/dns/edgedns"
	"github.com/go-acme/lego/v4/providers/dns/epik"
	"github.com/go-acme/lego/v4/providers/dns/exoscale"
	"github.com/go-acme/lego/v4/providers/dns/freemyip"
	"github.com/go-acme/lego/v4/providers/dns/gandi"
	"github.com/go-acme/lego/v4/providers/dns/gandiv5"
	"github.com/go-acme/lego/v4/providers/dns/gcloud"
	"github.com/go-acme/lego/v4/providers/dns/gcore"
	"github.com/go-acme/lego/v4/providers/dns/glesys"
	"github.com/go-acme/lego/v4/providers/dns/godaddy"
	"github.com/go-acme/lego/v4/providers/dns/googledomains"
	"github.com/go-acme/lego/v4/providers/dns/hetzner"
	"github.com/go-acme/lego/v4/providers/dns/hostingde"
	"github.com/go-acme/lego/v4/providers/dns/hosttech"
	"github.com/go-acme/lego/v4/providers/dns/httpreq"
	"github.com/go-acme/lego/v4/providers/dns/hurricane"
	"github.com/go-acme/lego/v4/providers/dns/hyperone"
	"github.com/go-acme/lego/v4/providers/dns/ibmcloud"
	"github.com/go-acme/lego/v4/providers/dns/iij"
	"github.com/go-acme/lego/v4/providers/dns/iijdpf"
	"github.com/go-acme/lego/v4/providers/dns/infoblox"
	"github.com/go-acme/lego/v4/providers/dns/infomaniak"
	"github.com/go-acme/lego/v4/providers/dns/internetbs"
	"github.com/go-acme/lego/v4/providers/dns/inwx"
	"github.com/go-acme/lego/v4/providers/dns/ionos"
	"github.com/go-acme/lego/v4/providers/dns/iwantmyname"
	"github.com/go-acme/lego/v4/providers/dns/joker"
	"github.com/go-acme/lego/v4/providers/dns/liara"
	"github.com/go-acme/lego/v4/providers/dns/lightsail"
	"github.com/go-acme/lego/v4/providers/dns/linode"
	"github.com/go-acme/lego/v4/providers/dns/liquidweb"
	"github.com/go-acme/lego/v4/providers/dns/loopia"
	"github.com/go-acme/lego/v4/providers/dns/luadns"
	"github.com/go-acme/lego/v4/providers/dns/mydnsjp"
	"github.com/go-acme/lego/v4/providers/dns/mythicbeasts"
	"github.com/go-acme/lego/v4/providers/dns/namecheap"
	"github.com/go-acme/lego/v4/providers/dns/namedotcom"
	"github.com/go-acme/lego/v4/providers/dns/namesilo"
	"github.com/go-acme/lego/v4/providers/dns/nearlyfreespeech"
	"github.com/go-acme/lego/v4/providers/dns/netcup"
	"github.com/go-acme/lego/v4/providers/dns/netlify"
	"github.com/go-acme/lego/v4/providers/dns/nicmanager"
	"github.com/go-acme/lego/v4/providers/dns/nifcloud"
	"github.com/go-acme/lego/v4/providers/dns/njalla"
	"github.com/go-acme/lego/v4/providers/dns/nodion"
	"github.com/go-acme/lego/v4/providers/dns/ns1"
	"github.com/go-acme/lego/v4/providers/dns/oraclecloud"
	"github.com/go-acme/lego/v4/providers/dns/otc"
	"github.com/go-acme/lego/v4/providers/dns/ovh"
	"github.com/go-acme/lego/v4/providers/dns/pdns"
	"github.com/go-acme/lego/v4/providers/dns/plesk"
	"github.com/go-acme/lego/v4/providers/dns/porkbun"
	"github.com/go-acme/lego/v4/providers/dns/rackspace"
	"github.com/go-acme/lego/v4/providers/dns/regru"
	"github.com/go-acme/lego/v4/providers/dns/rfc2136"
	"github.com/go-acme/lego/v4/providers/dns/rimuhosting"
	"github.com/go-acme/lego/v4/providers/dns/route53"
	"github.com/go-acme/lego/v4/providers/dns/safedns"
	"github.com/go-acme/lego/v4/providers/dns/sakuracloud"
	"github.com/go-acme/lego/v4/providers/dns/scaleway"
	"github.com/go-acme/lego/v4/providers/dns/selectel"
	"github.com/go-acme/lego/v4/providers/dns/servercow"
	"github.com/go-acme/lego/v4/providers/dns/simply"
	"github.com/go-acme/lego/v4/providers/dns/sonic"
	"github.com/go-acme/lego/v4/providers/dns/stackpath"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"github.com/go-acme/lego/v4/providers/dns/transip"
	"github.com/go-acme/lego/v4/providers/dns/ultradns"
	"github.com/go-acme/lego/v4/providers/dns/variomedia"
	"github.com/go-acme/lego/v4/providers/dns/vegadns"
	"github.com/go-acme/lego/v4/providers/dns/vercel"
	"github.com/go-acme/lego/v4/providers/dns/versio"
	"github.com/go-acme/lego/v4/providers/dns/vinyldns"
	"github.com/go-acme/lego/v4/providers/dns/vkcloud"
	"github.com/go-acme/lego/v4/providers/dns/vscale"
	"github.com/go-acme/lego/v4/providers/dns/vultr"
	"github.com/go-acme/lego/v4/providers/dns/websupport"
	"github.com/go-acme/lego/v4/providers/dns/wedos"
	"github.com/go-acme/lego/v4/providers/dns/yandex"
	"github.com/go-acme/lego/v4/providers/dns/yandexcloud"
	"github.com/go-acme/lego/v4/providers/dns/zoneee"
	"github.com/go-acme/lego/v4/providers/dns/zonomi"
)

var cache *fastcache.Cache
var settings *InitParameters

type InitParameters struct {
	// if zero, then we do not initialize any cache
	// otherwise the size in bytes of the in memory certificates cache.
	// If InMemoryCacheSize is less than 32MB, then the minimum cache capacity is 32MB.
	InMemoryCacheSize int

	CertificateContactEmail string

	Store storage.Store

	// Leave nil for no DNS challenges
	// We support only one DNS provider at a time
	DNSProvider *DNSProviderConfig

	// Each main map key correspond to a root domain name, e.g. example.com
	// Each sub map key correspond to a subdomain of the parent root domain, e.g. bob.example.com or *.example.com
	// Please note that the use of the wildcard operator * is only possible when you define a DNS provider for your domains
	AuthorizedDomains map[string]map[string]bool

	LogLevel LogLevel
	Logger   io.Writer
}

type DNSProviderConfig struct {
	AliDNS           *alidns.Config
	Allinkl          *allinkl.Config
	Arvancloud       *arvancloud.Config
	Azure            *azure.Config
	AuroraDNS        *auroradns.Config
	AutoDNS          *autodns.Config
	Bindman          *bindman.Config
	Bluecat          *bluecat.Config
	Brandit          *brandit.Config
	Bunny            *bunny.Config
	CheckDomain      *checkdomain.Config
	Civo             *civo.Config
	CloudDNS         *clouddns.Config
	Cloudflare       *cloudflare.Config
	CloudNS          *cloudns.Config
	CloudXNS         *cloudxns.Config
	ConoHa           *conoha.Config
	Constellix       *constellix.Config
	Derak            *derak.Config
	DeSEC            *desec.Config
	Designate        *designate.Config
	DigitalOcean     *digitalocean.Config
	DnsHomeDe        *dnshomede.Config
	Dnsimple         *dnsimple.Config
	Dnsmadeeasy      *dnsmadeeasy.Config
	Dnspod           *dnspod.Config
	Dode             *dode.Config
	Domeneshop       *domeneshop.Config
	Dreamhost        *dreamhost.Config
	Duckdns          *duckdns.Config
	Dyn              *dyn.Config
	Dynu             *dynu.Config
	EasyDNS          *easydns.Config
	Edgedns          *edgedns.Config
	Epik             *epik.Config
	Exoscale         *exoscale.Config
	FreeMyIP         *freemyip.Config
	Gandi            *gandi.Config
	Gandiv5          *gandiv5.Config
	GCloud           *gcloud.Config
	GCore            *gcore.Config
	Glesys           *glesys.Config
	GoDaddy          *godaddy.Config
	GoogleDomains    *googledomains.Config
	Hetzner          *hetzner.Config
	HostingDe        *hostingde.Config
	HostTech         *hosttech.Config
	Httpreq          *httpreq.Config
	Hurricane        *hurricane.Config
	Hyperone         *hyperone.Config
	IBMCloud         *ibmcloud.Config
	IIJ              *iij.Config
	IIJDPF           *iijdpf.Config
	Infoblox         *infoblox.Config
	Infomaniak       *infomaniak.Config
	InternetBS       *internetbs.Config
	Inwx             *inwx.Config
	Ionos            *ionos.Config
	IWantMyName      *iwantmyname.Config
	Joker            *joker.Config
	Liara            *liara.Config
	LightSail        *lightsail.Config
	Linode           *linode.Config
	LiquidWeb        *liquidweb.Config
	LuaDNS           *luadns.Config
	Loopia           *loopia.Config
	MyDNSJP          *mydnsjp.Config
	MythicBeasts     *mythicbeasts.Config
	Namecheap        *namecheap.Config
	NameDotCom       *namedotcom.Config
	NameSilo         *namesilo.Config
	NearlyFreeSpeech *nearlyfreespeech.Config
	Netcup           *netcup.Config
	Netlify          *netlify.Config
	NicManager       *nicmanager.Config
	Nifcloud         *nifcloud.Config
	Njalla           *njalla.Config
	Nodion           *nodion.Config
	NS1              *ns1.Config
	OracleCloud      *oraclecloud.Config
	OTC              *otc.Config
	OVH              *ovh.Config
	PDNS             *pdns.Config
	Plesk            *plesk.Config
	Porkbun          *porkbun.Config
	RackSpace        *rackspace.Config
	Regru            *regru.Config
	RFC2136          *rfc2136.Config
	RimuHosting      *rimuhosting.Config
	Route53          *route53.Config
	SafeDNS          *safedns.Config
	SakuraCloud      *sakuracloud.Config
	Scaleway         *scaleway.Config
	Selectel         *selectel.Config
	Servercow        *servercow.Config
	Simply           *simply.Config
	Sonic            *sonic.Config
	Stackpath        *stackpath.Config
	TencentCloud     *tencentcloud.Config
	Transip          *transip.Config
	UltraDNS         *ultradns.Config
	Variomedia       *variomedia.Config
	VegaDNS          *vegadns.Config
	Vercel           *vercel.Config
	Versio           *versio.Config
	VinylDNS         *vinyldns.Config
	VKCloud          *vkcloud.Config
	Vscale           *vscale.Config
	Vultr            *vultr.Config
	WebSupport       *websupport.Config
	Wedos            *wedos.Config
	Yandex           *yandex.Config
	YandexCloud      *yandexcloud.Config
	ZoneEE           *zoneee.Config
	Zonomi           *zonomi.Config
}

// Call Init before calling any other function
func Init(param *InitParameters) error {
	if param == nil {
		return fmt.Errorf("We need a non nil *InitParameters argument")
	}

	settings = param

	switch settings.Store.(type) {
	case nil:
		return fmt.Errorf("We need a Store in the parameters")
	}

	if settings.LogLevel != NONE {
		switch settings.Logger.(type) {
		case nil:
			return fmt.Errorf("We need a Logger in the parameters when the LogLevel is different from NONE")
		}
	}

	if settings.InMemoryCacheSize > 0 {
		cache = fastcache.New(settings.InMemoryCacheSize)
	}

	if settings.CertificateContactEmail == "" {
		return fmt.Errorf("We need a certificate contact email in the parameters")
	}

	_, err := mail.ParseAddress(settings.CertificateContactEmail)
	if err != nil {
		return fmt.Errorf("invalid certificate contact email address: %v", err)
	}

	if len(settings.AuthorizedDomains) == 0 {
		return fmt.Errorf("We need at least one authorized root domain name")
	}

	us, err := loadACMEUserFromDisk()
	if err != nil && err != storage.ErrNotFound {
		return err
	}

	if err == storage.ErrNotFound {
		// Create a user. New accounts need an email and private key to start.
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}

		us = &ACMEUser{
			Email: settings.CertificateContactEmail,
			key:   privateKey,
		}

		err = createHandler(us, true)
		if err != nil {
			return err
		}

		return nil
	}

	err = createHandler(us, false)
	if err != nil {
		return err
	}

	return nil
}
