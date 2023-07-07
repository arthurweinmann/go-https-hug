package acme

import (
	"fmt"

	"github.com/go-acme/lego/v4/challenge"
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

func newDNSChallenger(config *DNSProviderConfig) (challenge.Provider, error) {
	switch {
	case config.AliDNS != nil:
		return alidns.NewDNSProviderConfig(config.AliDNS)
	case config.Allinkl != nil:
		return allinkl.NewDNSProviderConfig(config.Allinkl)
	case config.Arvancloud != nil:
		return arvancloud.NewDNSProviderConfig(config.Arvancloud)
	case config.Azure != nil:
		return azure.NewDNSProviderConfig(config.Azure)
	case config.AuroraDNS != nil:
		return auroradns.NewDNSProviderConfig(config.AuroraDNS)
	case config.AutoDNS != nil:
		return autodns.NewDNSProviderConfig(config.AutoDNS)
	case config.Bindman != nil:
		return bindman.NewDNSProviderConfig(config.Bindman)
	case config.Bluecat != nil:
		return bluecat.NewDNSProviderConfig(config.Bluecat)
	case config.Brandit != nil:
		return brandit.NewDNSProviderConfig(config.Brandit)
	case config.Bunny != nil:
		return bunny.NewDNSProviderConfig(config.Bunny)
	case config.CheckDomain != nil:
		return checkdomain.NewDNSProviderConfig(config.CheckDomain)
	case config.Civo != nil:
		return civo.NewDNSProviderConfig(config.Civo)
	case config.CloudDNS != nil:
		return clouddns.NewDNSProviderConfig(config.CloudDNS)
	case config.Cloudflare != nil:
		return cloudflare.NewDNSProviderConfig(config.Cloudflare)
	case config.CloudNS != nil:
		return cloudns.NewDNSProviderConfig(config.CloudNS)
	case config.CloudXNS != nil:
		return cloudxns.NewDNSProviderConfig(config.CloudXNS)
	case config.ConoHa != nil:
		return conoha.NewDNSProviderConfig(config.ConoHa)
	case config.Constellix != nil:
		return constellix.NewDNSProviderConfig(config.Constellix)
	case config.Derak != nil:
		return derak.NewDNSProviderConfig(config.Derak)
	case config.DeSEC != nil:
		return desec.NewDNSProviderConfig(config.DeSEC)
	case config.Designate != nil:
		return designate.NewDNSProviderConfig(config.Designate)
	case config.DigitalOcean != nil:
		return digitalocean.NewDNSProviderConfig(config.DigitalOcean)
	case config.DnsHomeDe != nil:
		return dnshomede.NewDNSProviderConfig(config.DnsHomeDe)
	case config.Dnsimple != nil:
		return dnsimple.NewDNSProviderConfig(config.Dnsimple)
	case config.Dnsmadeeasy != nil:
		return dnsmadeeasy.NewDNSProviderConfig(config.Dnsmadeeasy)
	case config.Dnspod != nil:
		return dnspod.NewDNSProviderConfig(config.Dnspod)
	case config.Dode != nil:
		return dode.NewDNSProviderConfig(config.Dode)
	case config.Domeneshop != nil:
		return domeneshop.NewDNSProviderConfig(config.Domeneshop)
	case config.Dreamhost != nil:
		return dreamhost.NewDNSProviderConfig(config.Dreamhost)
	case config.Duckdns != nil:
		return duckdns.NewDNSProviderConfig(config.Duckdns)
	case config.Dyn != nil:
		return dyn.NewDNSProviderConfig(config.Dyn)
	case config.Dynu != nil:
		return dynu.NewDNSProviderConfig(config.Dynu)
	case config.EasyDNS != nil:
		return easydns.NewDNSProviderConfig(config.EasyDNS)
	case config.Edgedns != nil:
		return edgedns.NewDNSProviderConfig(config.Edgedns)
	case config.Epik != nil:
		return epik.NewDNSProviderConfig(config.Epik)
	case config.Exoscale != nil:
		return exoscale.NewDNSProviderConfig(config.Exoscale)
	case config.FreeMyIP != nil:
		return freemyip.NewDNSProviderConfig(config.FreeMyIP)
	case config.Gandi != nil:
		return gandi.NewDNSProviderConfig(config.Gandi)
	case config.Gandiv5 != nil:
		return gandiv5.NewDNSProviderConfig(config.Gandiv5)
	case config.GCloud != nil:
		return gcloud.NewDNSProviderConfig(config.GCloud)
	case config.GCore != nil:
		return gcore.NewDNSProviderConfig(config.GCore)
	case config.Glesys != nil:
		return glesys.NewDNSProviderConfig(config.Glesys)
	case config.GoDaddy != nil:
		return godaddy.NewDNSProviderConfig(config.GoDaddy)
	case config.GoogleDomains != nil:
		return googledomains.NewDNSProviderConfig(config.GoogleDomains)
	case config.Hetzner != nil:
		return hetzner.NewDNSProviderConfig(config.Hetzner)
	case config.HostingDe != nil:
		return hostingde.NewDNSProviderConfig(config.HostingDe)
	case config.HostTech != nil:
		return hosttech.NewDNSProviderConfig(config.HostTech)
	case config.Httpreq != nil:
		return httpreq.NewDNSProviderConfig(config.Httpreq)
	case config.Hurricane != nil:
		return hurricane.NewDNSProviderConfig(config.Hurricane)
	case config.Hyperone != nil:
		return hyperone.NewDNSProviderConfig(config.Hyperone)
	case config.IBMCloud != nil:
		return ibmcloud.NewDNSProviderConfig(config.IBMCloud)
	case config.IIJ != nil:
		return iij.NewDNSProviderConfig(config.IIJ)
	case config.IIJDPF != nil:
		return iijdpf.NewDNSProviderConfig(config.IIJDPF)
	case config.Infoblox != nil:
		return infoblox.NewDNSProviderConfig(config.Infoblox)
	case config.Infomaniak != nil:
		return infomaniak.NewDNSProviderConfig(config.Infomaniak)
	case config.InternetBS != nil:
		return internetbs.NewDNSProviderConfig(config.InternetBS)
	case config.Inwx != nil:
		return inwx.NewDNSProviderConfig(config.Inwx)
	case config.Ionos != nil:
		return ionos.NewDNSProviderConfig(config.Ionos)
	case config.IWantMyName != nil:
		return iwantmyname.NewDNSProviderConfig(config.IWantMyName)
	case config.Joker != nil:
		return joker.NewDNSProviderConfig(config.Joker)
	case config.Liara != nil:
		return liara.NewDNSProviderConfig(config.Liara)
	case config.LightSail != nil:
		return lightsail.NewDNSProviderConfig(config.LightSail)
	case config.Linode != nil: // "linodev4" is for compatibility with v3, must be dropped in v5
		return linode.NewDNSProviderConfig(config.Linode)
	case config.LiquidWeb != nil:
		return liquidweb.NewDNSProviderConfig(config.LiquidWeb)
	case config.LuaDNS != nil:
		return luadns.NewDNSProviderConfig(config.LuaDNS)
	case config.Loopia != nil:
		return loopia.NewDNSProviderConfig(config.Loopia)
	case config.MyDNSJP != nil:
		return mydnsjp.NewDNSProviderConfig(config.MyDNSJP)
	case config.MythicBeasts != nil:
		return mythicbeasts.NewDNSProviderConfig(config.MythicBeasts)
	case config.Namecheap != nil:
		return namecheap.NewDNSProviderConfig(config.Namecheap)
	case config.NameDotCom != nil:
		return namedotcom.NewDNSProviderConfig(config.NameDotCom)
	case config.NameSilo != nil:
		return namesilo.NewDNSProviderConfig(config.NameSilo)
	case config.NearlyFreeSpeech != nil:
		return nearlyfreespeech.NewDNSProviderConfig(config.NearlyFreeSpeech)
	case config.Netcup != nil:
		return netcup.NewDNSProviderConfig(config.Netcup)
	case config.Netlify != nil:
		return netlify.NewDNSProviderConfig(config.Netlify)
	case config.NicManager != nil:
		return nicmanager.NewDNSProviderConfig(config.NicManager)
	case config.Nifcloud != nil:
		return nifcloud.NewDNSProviderConfig(config.Nifcloud)
	case config.Njalla != nil:
		return njalla.NewDNSProviderConfig(config.Njalla)
	case config.Nodion != nil:
		return nodion.NewDNSProviderConfig(config.Nodion)
	case config.NS1 != nil:
		return ns1.NewDNSProviderConfig(config.NS1)
	case config.OracleCloud != nil:
		return oraclecloud.NewDNSProviderConfig(config.OracleCloud)
	case config.OTC != nil:
		return otc.NewDNSProviderConfig(config.OTC)
	case config.OVH != nil:
		return ovh.NewDNSProviderConfig(config.OVH)
	case config.PDNS != nil:
		return pdns.NewDNSProviderConfig(config.PDNS)
	case config.Plesk != nil:
		return plesk.NewDNSProviderConfig(config.Plesk)
	case config.Porkbun != nil:
		return porkbun.NewDNSProviderConfig(config.Porkbun)
	case config.RackSpace != nil:
		return rackspace.NewDNSProviderConfig(config.RackSpace)
	case config.Regru != nil:
		return regru.NewDNSProviderConfig(config.Regru)
	case config.RFC2136 != nil:
		return rfc2136.NewDNSProviderConfig(config.RFC2136)
	case config.RimuHosting != nil:
		return rimuhosting.NewDNSProviderConfig(config.RimuHosting)
	case config.Route53 != nil:
		return route53.NewDNSProviderConfig(config.Route53)
	case config.SafeDNS != nil:
		return safedns.NewDNSProviderConfig(config.SafeDNS)
	case config.SakuraCloud != nil:
		return sakuracloud.NewDNSProviderConfig(config.SakuraCloud)
	case config.Scaleway != nil:
		return scaleway.NewDNSProviderConfig(config.Scaleway)
	case config.Selectel != nil:
		return selectel.NewDNSProviderConfig(config.Selectel)
	case config.Servercow != nil:
		return servercow.NewDNSProviderConfig(config.Servercow)
	case config.Simply != nil:
		return simply.NewDNSProviderConfig(config.Simply)
	case config.Sonic != nil:
		return sonic.NewDNSProviderConfig(config.Sonic)
	case config.Stackpath != nil:
		return stackpath.NewDNSProviderConfig(config.Stackpath)
	case config.TencentCloud != nil:
		return tencentcloud.NewDNSProviderConfig(config.TencentCloud)
	case config.Transip != nil:
		return transip.NewDNSProviderConfig(config.Transip)
	case config.UltraDNS != nil:
		return ultradns.NewDNSProviderConfig(config.UltraDNS)
	case config.Variomedia != nil:
		return variomedia.NewDNSProviderConfig(config.Variomedia)
	case config.VegaDNS != nil:
		return vegadns.NewDNSProviderConfig(config.VegaDNS)
	case config.Vercel != nil:
		return vercel.NewDNSProviderConfig(config.Vercel)
	case config.Versio != nil:
		return versio.NewDNSProviderConfig(config.Versio)
	case config.VinylDNS != nil:
		return vinyldns.NewDNSProviderConfig(config.VinylDNS)
	case config.VKCloud != nil:
		return vkcloud.NewDNSProviderConfig(config.VKCloud)
	case config.Vscale != nil:
		return vscale.NewDNSProviderConfig(config.Vscale)
	case config.Vultr != nil:
		return vultr.NewDNSProviderConfig(config.Vultr)
	case config.WebSupport != nil:
		return websupport.NewDNSProviderConfig(config.WebSupport)
	case config.Wedos != nil:
		return wedos.NewDNSProviderConfig(config.Wedos)
	case config.Yandex != nil:
		return yandex.NewDNSProviderConfig(config.Yandex)
	case config.YandexCloud != nil:
		return yandexcloud.NewDNSProviderConfig(config.YandexCloud)
	case config.ZoneEE != nil:
		return zoneee.NewDNSProviderConfig(config.ZoneEE)
	case config.Zonomi != nil:
		return zonomi.NewDNSProviderConfig(config.Zonomi)
	default:
		return nil, fmt.Errorf("no dns provider provided")
	}
}
