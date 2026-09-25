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
""".split())
