"""Static word lists used by detectors and surrogate generators.

Name lists deliberately avoid surnames that are also common words
(e.g. "Braun", "Koch", "Wolf", "Young", "White") so that reverting
pseudonymised text does not accidentally replace ordinary words.
"""

FIRST_NAMES = """
Adrian Agnes Alena Alina Amelie Anika Annika Anton Arne Aurelia Bastian Benedikt
Benno Bettina Birte Bjarne Carina Carsten Cedric Clemens Corinna Cornelius Dajana
Damian Dario Dorian Edgar Elias Elin Emilia Enno Erik Esther Fabian Falk Farina
Felix Fenja Finja Florian Frederik Gesa Gregor Hanna Hauke Helena Henrik Ida Ilka
Ines Isabel Jakob Janek Jannik Jasper Jonas Jorin Josefine Julian Juna Kai Karla
Kilian Konrad Lale Lasse Leander Lennart Leonie Levin Liam Linus Lorenz Luisa
Lukas Magnus Maja Malte Marek Marit Mats Mila Milan Mira Moritz Nele Niklas Nils
Noah Ole Oskar Paula Pia Quirin Rasmus Rieke Ronja Ruben Sanna Selma Silas Simon
Smilla Stina Svea Talea Tamara Theo Thilo Tilda Timo Tjark Ulrike Valentin Vera
Veit Wiebke Xenia Yannik Yara Zoe Aiden Brody Caleb Chloe Dylan Evelyn Gavin
Harper Isla Jasmine Kendra Landon Logan Maddox Nolan Owen Piper Quinn Reagan
Rowan Sawyer Skylar Tessa Tristan Wyatt
""".split()

LAST_NAMES = """
Achterberg Albrecht Amsel Andernach Arnold Aschauer Bachmeier Baumgartner
Behrendt Bergmann Birkner Blumenthal Brandl Brunner Burkhardt Dannenberg Dietrich
Dorfmeister Eckhardt Ehrlich Eichler Engelhardt Falkenstein Feldmann Fleischer
Freitag Friedl Fuchsberger Gebhardt Gerstner Gottschalk Grabowski Grimmel Gruber
Haberland Hagedorn Hartmann Haslinger Heinemann Hellwig Herrmann Hinterberger
Hoffmeister Holzner Huber Jablonski Jungwirth Kaltenbach Kappler Kellermann
Kirchner Klingbeil Knoblauch Kollmann Kranzl Kretschmer Kuhnert Lamprecht
Landauer Lechner Leitner Lindemann Loibl Lorenzen Maierhofer Mangold Marquardt
Meisinger Moosbrugger Neuhauser Niedermeier Obermaier Ortlieb Pfeiffer Pichler
Plattner Pohlmann Prantl Radtke Rainer Reisinger Riedl Rosenthal Sailer
Sandmann Schirmer Schlegel Schwaiger Seidl Siebert Sonnleitner Stadler Steiner
Stockinger Strobl Thalhammer Trautmann Unterberger Vogler Wagenknecht
Waldhauser Weidinger Wendt Wieland Winkler Wollenberg Zeilinger Zimmerer
Ashcombe Blackwood Carrington Donnelly Eastwood Fairbanks Galloway Hargrove
Kensington Lockhart Montague Northcott Pemberton Radcliffe Sinclair Thornbury
Wakefield Whitmore
""".split()

# Syllables for pronounceable pseudo-words (organisation / domain labels).
SYLLABLE_ONSETS = "b br d dr f fl g gr h k kl kr l m n p pl pr r s st t tr v w z".split()
SYLLABLE_VOWELS = "a e i o u a e i o au ei".split()
SYLLABLE_CODAS = ["", "", "", "n", "r", "l", "s", "m", "x", "nd", "rt", "ck"]

# Labels that are generic infrastructure vocabulary and therefore not
# identifying on their own. They are kept inside hostnames/subdomains.
GENERIC_LABELS = set("""
www www1 www2 mail mails email smtp smtps imap imaps pop pop3 mx mx1 mx2 ns ns1 ns2
dns dns1 dns2 vpn api apis app apps web web1 web2 git gitlab github gitea jenkins
ci cd dev devel test tests testing stage staging stg prod production prd qa uat int
db db1 db2 sql mysql mariadb postgres pg redis mongo ldap ldaps ad dc dc1 dc2 fs
srv server servers host hosts node nodes master masters worker workers k8s kube
rke rke2 k3s cluster lb proxy rproxy gw gateway fw firewall router rtr sw switch
ap wlan wifi portal admin intranet extranet auth sso login id idp oidc saml
keycloak authentik vault backup backups bak nas san storage s3 minio ceph pve
proxmox esx esxi vcenter vc exchange owa autodiscover autoconfig lync sip voip pbx
monitor monitoring mon grafana prometheus alertmanager zabbix nagios icinga log
logs logging elk kibana loki siem wazuh graylog cdn static assets img images media
files file share shares docs doc wiki help support status shop blog crm erp hr
print printer printers scan cam cams nvr iot mqtt ha home lab office cloud remote
rdp rds rdweb citrix ts terminal jump jumphost bastion mgmt management ilo idrac
ipmi bmc oob internal external public private local corp net old new v1 v2 v3
secure ssl tls cert certs ca pki ocsp crl ntp time update updates repo repos
registry harbor nexus artifactory npm pypi docker kubernetes argocd argo rancher
traefik nginx apache iis tomcat ingress egress edge core svc service services
default kube-system system app1 app2 api1 api2 my the a an our demo sandbox
intern extern m mobile beta alpha preview dashboard console panel metrics trace
tracing jaeger sentry sonar sonarqube nextcloud cloudflare paperless plex
""".split())

# Parts of infrastructure names (Kubernetes, Helm, Compose …) that say what a thing IS,
# not whose it is. They stay when "bunkerweb-front" or "kunde-mueller-prod" is pseudonymised.
INFRA_GENERIC = set("""
front frontend back backend api apis app apps web ui gui site www server srv service svc
services worker workers scheduler sched controller controllers manager mgr operator operators
agent agents daemon exporter exporters collector sidecar proxy gateway gw ingress egress lb
balancer router cache queue broker bus stream streams cron cronjob job jobs batch task tasks
runner runners build builder deploy deployment deployments release releases instance instances
main master primary secondary replica replicas slave leader follower node nodes pool pools
cluster clusters core common shared base lib libs config configs conf settings secret secrets
env data db database databases store storage volume volumes pvc pv disk disks backup backups
snapshot snapshots archive archives log logs logging metrics metric monitor monitoring alert
alerts alerting trace tracing health healthcheck status probe init migrate migration migrations
seed setup install installer upgrade hook hooks webhook webhooks admin admins dashboard
portal console panel auth authn authz sso oauth oidc login user users account accounts
mail smtp dns ntp vpn http https grpc tcp udp tls ssl cert certs ca crd crds rbac role roles
binding bindings sa ns namespace namespaces system kube default public private internal
external intern extern local global prod production prd staging stage stg dev develop
development test tests testing qa uat int integration demo sandbox preview canary blue green
stable latest edge nightly alpha beta rc v1 v2 v3 old new legacy primary blue green
east west north south eu us de at ch emea apac region zone zones rack
kunde kunden customer customers client clients tenant tenants team teams project projects
app1 app2 web1 web2 api1 api2 db1 db2 one two three first second
headless internal external default chart charts values template templates
redis-master redis-replicas
package packages file files folder folders dir group groups update updates upgrade install
remove create delete copy restart start stop check checks validate verify run exec script
scripts tool tools util utils helper helpers plugin plugins module modules extension
extensions theme themes content upload uploads media image images video audio font fonts
static assets public src source dist bin lib include vendor home root tmp temp cache report
reports export import sync mirror docs doc readme example examples sample samples dummy foo
bar baz produktiv entwicklung abnahme schulung mandant mandanten standort zentrale filiale
lager buero verwaltung
""".split())

# Public product/project names that often appear in infrastructure names; they carry
# useful context and are not secret, so they are not pseudonymised.
INFRA_PRODUCTS = set("""
bunkerweb nginx apache httpd caddy haproxy envoy traefik squid varnish tomcat jetty
redis valkey memcached postgres postgresql pg pgbouncer patroni mysql mariadb galera mongo
mongodb cassandra couchdb clickhouse influxdb timescaledb elasticsearch elastic opensearch
kibana logstash beats filebeat metricbeat fluentd fluent fluentbit vector loki promtail tempo
mimir thanos cortex grafana prometheus alertmanager pushgateway jaeger zipkin otel
opentelemetry kafka zookeeper rabbitmq nats mosquitto emqx activemq pulsar minio ceph rook
longhorn openebs velero kopia restic etcd coredns kubedns calico cilium flannel weave
metallb kube-vip istio linkerd consul vault nomad terraform ansible awx argocd argo flux
fluxcd helm kustomize rancher rke rke2 k3s k8s kubernetes kubelet kubectl containerd docker
podman buildkit kaniko harbor nexus artifactory registry gitlab gitea github jenkins drone
woodpecker tekton sonarqube sonar trivy falco kyverno gatekeeper opa certmanager cert-manager
externaldns external-dns sealed sealed-secrets keycloak authentik authelia dex oauth2-proxy
freeipa openldap ldap samba nextcloud collabora onlyoffice wordpress drupal joomla mediawiki
mattermost rocketchat synapse matrix element jitsi bigbluebutton zabbix icinga nagios checkmk
wazuh graylog splunk netbird wireguard openvpn tailscale headscale pihole adguard unbound bind
powerdns postfix dovecot rspamd clamav mailcow homeassistant mosquitto nodered plex jellyfin
emby paperless ollama openwebui vllm litellm comfyui stable-diffusion n8n airflow superset
metabase jupyter jupyterhub mlflow spark hadoop hive trino presto flink dask ray kubeflow
proxmox pve esxi vcenter vmware hyperv opnsense pfsense securepoint fortigate fortinet sophos
python node nodejs java golang php ruby dotnet
""".split())

# Public domains of tools whose names appear in Kubernetes label/annotation keys,
# CRD groups and API versions; they are never pseudonymised.
PUBLIC_TECH_DOMAINS = set("""
k8s.io x-k8s.io kubernetes.io helm.sh argoproj.io cert-manager.io acme.cert-manager.io
prometheus.io coreos.com monitoring.coreos.com istio.io traefik.io containo.us linkerd.io
knative.dev fluxcd.io toolkit.fluxcd.io cilium.io projectcalico.org tigera.io longhorn.io
cattle.io velero.io external-secrets.io bitnami.com opentelemetry.io keda.sh kyverno.io
gatekeeper.sh jetstack.io metallb.io nginx.org min.io rook.io ceph.io grafana.com
elastic.co hashicorp.com rancher.com k3s.io rke2.io vmware.com openshift.io redhat.com
docker.com docker.io quay.io ghcr.io gcr.io registry.k8s.io mcr.microsoft.com
containerd.io podman.io buildah.io cri-o.io kubeflow.org etcd.io coredns.io
debian.org ubuntu.com canonical.com fedoraproject.org centos.org rockylinux.org almalinux.org
alpinelinux.org archlinux.org opensuse.org suse.com gentoo.org kali.org linuxmint.com
proxmox.com kernel.org gnu.org freebsd.org openbsd.org python.org pypi.org npmjs.com
nodejs.org golang.org go.dev rust-lang.org crates.io rubygems.org
""".split())

# URL parameters that only say where a link came from / who clicked it.
TRACKING_PARAMS = set("""
fbclid gclid gclsrc dclid gbraid wbraid msclkid twclid ttclid yclid ysclid li_fat_id
mc_cid mc_eid mkt_tok _hsenc _hsmi hsctatracking __hssc __hstc __hsfp vero_id vero_conv
oly_anon_id oly_enc_id rb_clickid s_cid ml_subscriber ml_subscriber_hash wickedid
_openstat igshid igsh epik _ga _gl _gac cmpid ncid sr_share mbid trk trkemail
fb_action_ids fb_action_types fb_ref fb_source action_object_map action_type_map
action_ref_map ref_src ref_url spm scm share_id sharesource share_source sc_cid
et_rid sfmc_id sfmc_activityid ss_source ss_campaign_id ss_email_id cvid ocid ebisu
wt_mc wt_zmc wt_ref at_medium at_campaign at_campaign_type at_creation at_emailtype at_link
at_link_id at_link_origin at_link_type at_ptr_name at_recipient_id at_recipient_list
at_send_date gad_source gad_campaignid srsltid
""".split())
TRACKING_PREFIXES = ("utm_", "pk_", "mtm_", "piwik_", "hsa_", "__hs", "pf_rd_", "pd_rd_",
                     "matomo_", "stm_", "_bta_", "vgo_ee")
# Parameters that are tracking only on these sites (elsewhere "si" or "t" mean something else).
TRACKING_SITE_PARAMS = [
    (("youtube.com", "youtu.be", "youtube-nocookie.com"), {"si", "feature", "pp"}),
    (("spotify.com", "spotify.link"), {"si", "nd"}),
    (("twitter.com", "x.com"), {"s", "t", "ref_src", "ref_url"}),
    (("instagram.com",), {"igshid", "igsh"}),
    (("tiktok.com",), {"_t", "_r", "is_from_webapp", "sender_device", "sender_web_id", "share_app_id",
                       "share_item_id", "share_link_id", "tt_from", "u_code", "timestamp", "user_id", "utm_campaign"}),
    (("linkedin.com", "lnkd.in"), {"trackingid", "lipi", "midtoken", "midsig", "eid", "refid", "trk",
                                   "trkemail", "rcm", "origin"}),
    (("facebook.com", "fb.com", "fb.me", "messenger.com"), {"mibextid", "__cft__", "__tn__", "ref",
                                                             "rdid", "share_url", "sfnsn", "hc_ref"}),
    (("google.*",), {"ved", "ei", "sa", "usg", "oq", "aqs", "sourceid", "gs_lcrp", "gs_lp", "sclient",
                     "bih", "biw", "uact", "rlz", "sxsrf", "iflsig", "gs_l", "sca_esv", "sca_upv"}),
    (("amazon.*",), {"ref", "ref_", "_encoding", "content-id", "crid", "sprefix", "qid", "dib", "dib_tag",
                     "sr", "linkcode", "linkid", "tag", "ascsubtag", "creativeasin", "creative", "camp"}),
    (("reddit.com", "redd.it"), {"share_id", "ref_source", "ref", "rdt"}),
    (("medium.com",), {"source"}),
    (("ebay.*",), {"_trkparms", "_trksid", "hash", "amdata", "mkcid", "mkrid", "campid", "toolid", "mkevt"}),
    (("aliexpress.com",), {"spm", "scm", "pvid", "algo_pvid", "algo_exp_id", "aff_platform", "aff_trace_key",
                           "sk", "terminal_id", "afsmartredirect", "gatewayadapt"}),
]
# Redirect wrappers: (host regex, path regex, query keys holding the real target).
REDIRECT_WRAPPERS = [
    (r".*safelinks\.protection\.outlook\.com", r"/", ("url",)),
    (r"statics\.teams\.cdn\.office\.net", r"/evergreen-assets/safelinks/", ("url",)),
    (r"(www\.)?google\.[a-z.]+", r"/url", ("q", "url")),
    (r"(l|lm|m)\.facebook\.com", r"/l\.php", ("u",)),
    (r"(www\.)?linkedin\.com", r"/(redir/redirect|safety/go)", ("url",)),
    (r"slack-redir\.net", r"/link", ("url",)),
    (r"(www\.)?youtube\.com", r"/redirect", ("q",)),
    (r"steamcommunity\.com", r"/linkfilter", ("url", "u")),
    (r"(html\.)?duckduckgo\.com", r"/l/", ("uddg",)),
    (r"(www\.)?bing\.com", r"/ck/a", ("u",)),
    (r"out\.reddit\.com", r"/", ("url",)),
    (r"t\.umblr\.com", r"/redirect", ("z",)),
    (r"l\.instagram\.com", r"/", ("u",)),
]

# Large public companies/projects: the NER plugin finds them everywhere (vendor names in
# logs, stack traces, docs); they are no personal or customer data.
PUBLIC_ORGS = set("""
microsoft google alphabet apple amazon aws meta facebook oracle ibm sap cisco intel amd nvidia
adobe salesforce vmware broadcom dell hp hpe lenovo samsung sony siemens bosch telekom vodafone
red hat redhat canonical suse mozilla github gitlab docker kubernetes linux apache python
openai anthropic cloudflare akamai fortinet paloalto palo alto networks checkpoint sophos
eset kaspersky crowdstrike okta atlassian jira confluence slack zoom teams windows azure
office outlook exchange sharepoint avalonia dotnet java spring jetbrains visual studio
gnu debian ubuntu kubuntu xubuntu fedora centos rhel rocky almalinux alpine arch archlinux gentoo
kali mint opensuse sles freebsd openbsd netbsd raspbian proxmox truenas opnsense pfsense nixos
manjaro devuan slackware android ios macos unix bookworm bullseye buster trixie sid jammy noble
focal bionic
""".split())
# words that do not make a name private on their own ("Debian GNU/Linux", "Ubuntu Server LTS")
PUBLIC_ORG_EXTRA_WORDS = set("""
server desktop edition enterprise linux lts workstation core pro professional home cloud
community stable testing unstable release version os
""".split()) | {"red hat", "palo alto networks", "check point", "visual studio", "google cloud",
                "microsoft azure", "amazon web services", "deutsche telekom"}

# Mailbox local parts that are functional rather than personal.
FUNCTIONAL_MAILBOXES = set("""
info admin administrator support noreply no-reply donotreply do-not-reply
postmaster abuse hostmaster webmaster security it service kontakt contact office
mail sales vertrieb buchhaltung billing invoice rechnung hr jobs karriere career
bewerbung datenschutz privacy dpo root helpdesk servicedesk team hello hallo
newsletter marketing presse press legal compliance ops devops alerts alert
monitoring notifications notification bounce bounces mailer-daemon git
""".split())

# Account names that are not personal.
SKIP_USERNAMES = set("""
root admin administrator public default all users default user guest system
ubuntu debian centos ec2-user pi git www-data nobody daemon postgres mysql
localadmin svc service
""".split())

# Legal-form suffixes kept verbatim in organisation names.
LEGAL_FORMS = set("""
gmbh ag kg ohg gbr ug e.v. ev eg se kgaa mbh co ltd limited inc incorporated corp
corporation llc llp plc sa sarl sas bv nv oy ab as aps spa srl gmbh&co
""".split())

# Receivers that show up in code as ``receiver.attribute`` and would otherwise
# look like domain names with a collision-prone TLD (``logger.info``,
# ``user.name``, ``threading.local``).
CODE_RECEIVERS = set("""
self this cls os sys re np pd obj ctx req res request response window document
console math json yaml logging logger log super props state event evt e err error
item it x y i j k v t s m a b c d f g h n p q r u w z module exports process path
args kwargs opts options settings config cfg conf env datetime date time threading
asyncio subprocess pathlib typing collections string str int list dict set plt tf
torch nn db session model models forms views urls user users file files stream
sock vm scope ng vue react angular expect should assert mock spy test describe row
col el elem element entry record rec doc msg message payload body result ret out
output input inp params param query form field meta attrs attr instance inst target
source src dst parent child node data value values key keys obj1 obj2 app api
client server service store router page link run host name id info local top
""".split())

# ccTLDs that are also common file extensions; accepted only in URL/e-mail
# context or when listed as a known domain.
FILE_EXT_TLDS = set("py sh md rs pl ps so cc ai ml mk in am ac pm gd cl mm sc zip mov bz tk cs ts do to is as".split())

# gTLD/ccTLDs that collide with frequent code attributes; accepted only if the
# first label is not a known code receiver and the text is not followed by "(".
CODEY_TLDS = set("""
id name info local app dev store date run test host page link one top live new
email fit win bid day style shop show club site online tech cloud group services
systems solutions digital data me it no us be at de io co tv
""".split())

GENERIC_TLDS = set("""
com net org info biz edu gov mil int eu app dev cloud online site tech store shop
xyz top club blog digital solutions systems services consulting agency group
gmbh berlin bayern hamburg koeln cologne nrw wien swiss tirol saarland ruhr
io co ai me tv cc name pro mobi asia travel jobs museum aero coop email link live
page run one day news media network software company expert academy center
support world today space website studio design art team zone life fit win bid
date style show host security social studio consulting engineering finance
local lan intern internal corp home localdomain arpa test
""".split())

CC_TLDS = set("""
ac ad ae af ag al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo
br bs bt bw by bz ca cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm
do dz ec ee eg er es et eu fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq
gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg
kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml
mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa
pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk
sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz
ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw
""".split())

ALL_TLDS = GENERIC_TLDS | CC_TLDS

# Multi-label public suffixes (subset of the Public Suffix List).
MULTI_SUFFIXES = set("""
co.uk org.uk ac.uk gov.uk ltd.uk plc.uk me.uk net.uk com.au net.au org.au edu.au
gov.au co.nz org.nz co.at or.at ac.at gv.at co.jp ne.jp or.jp ac.jp com.br net.br
com.cn net.cn org.cn com.tr com.pl net.pl org.pl co.za com.mx com.ar co.il co.in
com.sg com.hk com.tw co.kr home.arpa in-addr.arpa ip6.arpa priv.at
""".split())

# Suffixes treated as internal pseudo-TLDs.
INTERNAL_TLDS = set("local lan intern internal corp home localdomain test".split())

# Domains that are left untouched by default (public, non-identifying).
DEFAULT_ALLOWLIST_DOMAINS = """
example.com example.org example.net example.de localhost cluster.local
svc.cluster.local github.com gitlab.com githubusercontent.com microsoft.com
windows.com office.com office365.com live.com outlook.com azure.com google.com
googleapis.com gstatic.com youtube.com apple.com icloud.com amazon.com
amazonaws.com cloudflare.com python.org pypi.org npmjs.com npmjs.org docker.com
docker.io quay.io ghcr.io k8s.io kubernetes.io debian.org ubuntu.com
canonical.com redhat.com fedoraproject.org archlinux.org mozilla.org wikipedia.org
stackoverflow.com letsencrypt.org digicert.com w3.org ietf.org iana.org gnu.org
kernel.org openssl.org nginx.org apache.org helm.sh proxmox.com anthropic.com
openai.com huggingface.co gmail.com googlemail.com web.de gmx.de gmx.net t-online.de
schema.org json-schema.org xmlsoap.org
""".split()

# Built-in placeholder values that are not real secrets.
PLACEHOLDER_SECRETS = set("""
true false yes no on off null none nil undefined required optional
redacted [redacted] xxx xxxx xxxxx *** **** ***** ******** your-password
your_password yourpassword your-token your_token
changeme change-me change_me changeit secret password passwort token dummy example sample placeholder
todo tbd test foo bar baz qux hunter2 value
""".split())


# ------------------------------------------------------------------ dictionaries
# Built by tools/make_wordlists.py: the most frequent English/German words (wordfreq,
# CC BY-SA 4.0) and place names made of such words (GeoNames, CC BY 4.0).
_DICT: dict[str, frozenset] = {}


def _load(name: str) -> frozenset:
    if name not in _DICT:
        import gzip
        from ..paths import resource_path
        try:
            with gzip.open(resource_path("wordlists", name), "rt", encoding="utf-8") as fh:
                _DICT[name] = frozenset(fh.read().split("\n"))
        except OSError:
            _DICT[name] = frozenset()
    return _DICT[name]


def common_words() -> frozenset:
    return _load("common.txt.gz")


def english_words() -> frozenset:
    return _load("common_en.txt.gz")


def place_names() -> frozenset:
    return _load("places.txt.gz")


# first names that are also everyday words ("Per Doppelklick", "Will Smith" vs. "will")
AMBIGUOUS_FIRST_NAMES = set("""
per will may can mark grant bill chase pat jan mai april june august ob um am an ab so de la le van von
art hope joy faith rich sunny summer winter lane dean major king rose ray
""".split())


def is_first_name(word: str) -> bool:
    """First names (nam_dict, GNU FDL) – compared lower case and without accents; not the ones
    that are everyday words as well."""
    import unicodedata
    if word.lower() in AMBIGUOUS_FIRST_NAMES:
        return False
    folded = "".join(c for c in unicodedata.normalize("NFKD", word.lower()) if not unicodedata.combining(c))
    return folded in _load("firstnames.txt.gz")


def is_common_word(word: str) -> bool:
    """``word`` (any case) or its singular is one of the frequent English/German words."""
    w = word.lower()
    common = common_words()
    if w in common:
        return True
    if w.endswith("ies") and w[:-3] + "y" in common:
        return True
    if w.endswith("es") and w[:-2] in common:
        return True
    return w.endswith("s") and w[:-1] in common
