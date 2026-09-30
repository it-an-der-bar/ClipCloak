"""Test corpus for secret detection: what must be found, and what must stay.

All credentials are generated at run time from a fixed seed, so no token-shaped literal is in the
sources (secret scanners such as GitHub push protection would block the push) and every run sees
the same values. Prefixes are split ("gh" + "p_") for the same reason.

``positives()``: (name, text, core) – ``core`` is the random part that must be gone after redaction.
``negatives()``: (name, text) – nothing in it may be reported as a secret.
"""

from __future__ import annotations

import base64
import random
import string
import uuid

LOWER, UPPER, DIGITS = string.ascii_lowercase, string.ascii_uppercase, string.digits
B62 = LOWER + UPPER + DIGITS
B64URL = B62 + "-_"
B64 = B62 + "+/"
HEX = "0123456789abcdef"
UPNUM = UPPER + DIGITS
LOWNUM = LOWER + DIGITS
BECH32 = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"


class Gen:
    def __init__(self, seed: int = 4711):
        self.r = random.Random(seed)

    def s(self, alphabet: str, n: int) -> str:
        # every class of the alphabet at least once (a real token of 30+ random chars nearly always is)
        while True:
            out = "".join(self.r.choice(alphabet) for _ in range(n))
            need = [c for c in (LOWER, UPPER, DIGITS) if any(x in alphabet for x in c)]
            if n < 12 or all(any(x in c for x in out) for c in need):
                return out

    def b64(self, nbytes: int, urlsafe: bool = False, pad: bool = True) -> str:
        raw = bytes(self.r.randrange(256) for _ in range(nbytes))
        out = (base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)).decode()
        return out if pad else out.rstrip("=")

    def uuid(self) -> str:
        return str(uuid.UUID(int=self.r.getrandbits(128), version=4))

    def password(self, n: int = 20) -> str:
        sym = "!#$%&*+-=?@^_~"
        while True:
            p = "".join(self.r.choice(B62 + sym) for _ in range(n))
            if any(c in sym for c in p) and any(c.isdigit() for c in p) and any(c.isupper() for c in p):
                return p


def _vendor(g: Gen) -> list[tuple[str, str, str]]:
    """(name, token, core): well-known formats."""
    out = []

    def add(name, prefix, core, suffix=""):
        out.append((name, prefix + core + suffix, core))

    for p in ("p", "o", "u", "s", "r"):
        add("github-" + p, "gh" + p + "_", g.s(B62, 36))
    core = g.s(B62, 22) + "_" + g.s(B62, 59)
    add("github-fine", "github" + "_pat_", core)
    add("gitlab-pat", "gl" + "pat-", g.s(B62 + "-_", 20))
    add("gitlab-runner", "gl" + "rt-", g.s(B62 + "-_", 20))
    add("gitlab-deploy", "gl" + "dt-", g.s(B62 + "-_", 20))
    add("aws-key-id", "AK" + "IA", g.s(UPNUM, 16))
    add("slack-bot", "xo" + "xb-", g.s(DIGITS, 11) + "-" + g.s(DIGITS, 13) + "-" + g.s(B62, 24))
    add("slack-user", "xo" + "xp-", g.s(DIGITS, 11) + "-" + g.s(DIGITS, 13) + "-" + g.s(DIGITS, 13) + "-" + g.s(HEX, 32))
    add("anthropic", "sk-" + "ant-api03-", g.s(B64URL, 93), "AA")
    add("openai-proj", "sk-" + "proj-", g.s(B64URL, 64))
    add("openai-legacy", "sk-", g.s(B62, 20) + "T3Blbk" + "FJ" + g.s(B62, 20))
    add("google-api", "AI" + "za", g.s(B64URL, 35))
    add("stripe-live", "sk" + "_live_", g.s(B62, 24))
    add("stripe-restricted", "rk" + "_live_", g.s(B62, 24))
    add("npm", "np" + "m_", g.s(B62, 36))
    add("pypi", "py" + "pi-AgEIcHlwaS5vcmc", g.s(B64URL, 70))
    add("docker-hub", "dc" + "kr_pat_", g.s(B64URL, 27))
    add("vault-service", "hv" + "s.", g.s(B62, 24) + g.s(B64URL, 70))
    add("huggingface", "h" + "f_", g.s(LOWER + UPPER, 34))
    add("sendgrid", "S" + "G.", g.s(B64URL, 22) + "." + g.s(B64URL, 43))
    add("twilio-key", "S" + "K", g.s(HEX, 32))
    add("digitalocean", "do" + "p_v1_", g.s(HEX, 64))
    add("shopify", "sh" + "pat_", g.s(HEX, 32))
    add("linear", "li" + "n_api_", g.s(B62, 40))
    add("postman", "PM" + "AK-", g.s(HEX, 24) + "-" + g.s(HEX, 34))
    add("grafana-sa", "gl" + "sa_", g.s(B62, 32) + "_" + g.s(HEX, 8))
    add("grafana-cloud", "gl" + "c_", g.b64(60))
    add("newrelic", "NR" + "AK-", g.s(UPNUM, 27))
    add("doppler", "dp" + ".pt.", g.s(B62, 43))
    add("pulumi", "pu" + "l-", g.s(HEX, 40))
    add("databricks", "da" + "pi", g.s(HEX, 32))
    add("supabase", "sb" + "p_", g.s(HEX, 40))
    add("airtable", "pa" + "t", g.s(B62, 14) + "." + g.s(HEX, 64))
    add("groq", "gs" + "k_", g.s(B62, 52))
    add("openrouter", "sk-" + "or-v1-", g.s(HEX, 64))
    add("age", "AGE-" + "SECRET-KEY-1", g.s(BECH32, 58))
    add("telegram-bot", "", g.s(DIGITS, 10) + ":AA" + g.s(B64URL, 33))
    add("k3s-node-token", "K1" + "0", g.s(HEX, 64) + "::server:" + g.s(HEX, 32))
    add("azure-ad-secret", "", g.s(B62, 3) + "8Q~" + g.s(B62 + "_~.-", 34))
    add("rancher", "token-" + g.s(LOWNUM, 5) + ":", g.s(LOWNUM, 54))
    add("jwt", "", "ey" + "J" + g.b64(20, True, False) + ".ey" + "J" + g.b64(40, True, False) + "." + g.b64(32, True, False))
    return out


def _random_tokens(g: Gen) -> list[tuple[str, str, str]]:
    """Formats no rule knows: only randomness gives them away."""
    out = []
    for i, pre in enumerate(("vbk_", "abc-", "tok_", "xyz_", "ak-", "mk_live_", "srv.", "")):
        core = g.b64(32, urlsafe=True, pad=False)
        out.append((f"random-b64url-prefix-{i}", pre + core, core))
    for n in (30, 32, 40, 48, 64):
        core = g.s(B62, n)
        out.append((f"random-b62-{n}", core, core))
    for n in (32, 48):
        core = g.b64(n)
        out.append((f"random-b64-{n}", core, core))
    core = g.b64(32)
    out.append(("wireguard-key", core, core))
    core = g.s(B64, 40)
    out.append(("aws-secret-like", core, core))
    return out


def _half(tok: str) -> int:
    return len(tok) // 2


def _third(tok: str) -> tuple[int, int]:
    return len(tok) // 3, 2 * len(tok) // 3


# (name, tok -> text). Keys are neutral on purpose ("value", "data", "x"): the token itself must give
# it away, not a "password:" in front of it.
WRAPPERS = [
    ("alone", lambda t: t),
    ("alone-newline", lambda t: t + "\r\n"),
    ("sentence", lambda t: f"Hier der Token für den Build: {t} – bitte nicht weitergeben."),
    ("neutral", lambda t: f"Kannst du das mal eintragen: {t} – danke dir!"),
    ("log", lambda t: f"2026-09-29T17:02:11Z INFO worker[3]: using {t} for upload"),
    ("end-of-sentence", lambda t: f"Der Wert ist {t}."),
    ("comma", lambda t: f"{t}, danach neu starten"),
    ("parens", lambda t: f"Neuer Wert ({t}) ist aktiv"),
    ("brackets", lambda t: f"values: [{t}]"),
    ("angle", lambda t: f"Siehe <{t}> im Ticket"),
    ("double-quotes", lambda t: f'x = "{t}"'),
    ("single-quotes", lambda t: f"x = '{t}'"),
    ("backticks", lambda t: f"Setz `{t}` in die Config"),
    ("md-block", lambda t: f"```\n{t}\n```"),
    ("json", lambda t: f'{{"value": "{t}", "n": 1}}'),
    ("json-escaped", lambda t: f'"{{\\"value\\": \\"{t}\\"}}"'),
    ("yaml", lambda t: f"spec:\n  data: {t}\n  replicas: 2\n"),
    ("env", lambda t: f"FOO={t}\nBAR=1\n"),
    ("xml", lambda t: f"<entry><value>{t}</value></entry>"),
    ("html-attr", lambda t: f'<div data-x="{t}"></div>'),
    ("header", lambda t: f"X-Custom: {t}"),
    ("url-query", lambda t: f"https://api.example.org/v1/items?id=5&q={t}&page=2"),
    ("url-hook", lambda t: f"https://hooks.example.org/hooks/{t}"),
    ("cli", lambda t: f"tool run --value {t} --verbose"),
    ("csv", lambda t: f"id,name,value\n7,build,{t}\n"),
    ("tsv", lambda t: f"7\tbuild\t{t}\tok"),
    ("comment", lambda t: f"# alter Wert: {t}\nx = 1"),
    ("py-split", lambda t: f'value = (\n    "{t[:_half(t)]}"\n    "{t[_half(t):]}"\n)'),
    ("py-split3", lambda t: f'value = (\n    "{t[:_third(t)[0]]}"\n    "{t[_third(t)[0]:_third(t)[1]]}"\n'
                            f'    "{t[_third(t)[1]:]}"\n)'),
    ("js-concat", lambda t: f'const value = "{t[:_half(t)]}" +\n  "{t[_half(t):]}";'),
    ("java-concat", lambda t: f'String value = "{t[:_half(t)]}" + "{t[_half(t):]}";'),
    ("vb-concat", lambda t: f'Dim value = "{t[:_half(t)]}" & _\n    "{t[_half(t):]}"'),
    ("php-concat", lambda t: f"$value = '{t[:_half(t)]}' . '{t[_half(t):]}';"),
]


def positives(seed: int = 4711) -> list[tuple[str, str, str]]:
    g = Gen(seed)
    toks = _vendor(g) + _random_tokens(g)
    out: list[tuple[str, str, str]] = []
    # every token in every wrapper: text, code, config, markup, split over string literals, encoded
    for name, tok, core in toks:
        for wname, wrap in WRAPPERS:
            out.append((f"{name}/{wname}", wrap(tok), core))
        enc = base64.b64encode(tok.encode()).decode()
        out.append((f"{name}/base64", f"value: {enc}", enc))
    # 4. contexts
    pw = g.password(18)
    ctx = [
        ("env", "DB_PASSWORD={v}\nDB_HOST=db01\n", pw),
        ("env-export", 'export API_TOKEN="{v}"', g.s(B62, 32)),
        ("yaml", "database:\n  user: app\n  password: {v}\n", pw),
        ("json", '{{"client_id": "portal", "client_secret": "{v}"}}', g.s(B64URL, 40)),
        ("xml", "<connection><password>{v}</password></connection>", pw),
        ("ini", "[smtp]\npassword = {v}\n", pw),
        ("connstr", "Server=sql01;Database=crm;User Id=svc;Password={v};Encrypt=True", pw),
        ("url-cred", "postgres://app:{v}@db.example.org:5432/app", g.s(B62, 20)),
        ("git-cred", "https://ci-bot:{v}@git.example.org/group/repo.git", g.s(B62 + "-_", 26)),
        ("curl-user", "curl -u admin:{v} https://api.example.org/v1/status", g.s(B62, 16)),
        ("curl-header", 'curl -H "Authorization: Bearer {v}" https://api.example.org', g.s(B62, 40)),
        ("x-api-key", "X-Api-Key: {v}", g.s(B62, 32)),
        ("apim", "Ocp-Apim-Subscription-Key: {v}", g.s(HEX, 32)),
        ("query", "https://api.example.org/v2/items?limit=5&access_token={v}&page=2", g.s(B62, 40)),
        ("mysql", "mysql -u root -p{v} crm", g.s(B62, 14)),
        ("sshpass", "sshpass -p '{v}' ssh root@10.0.0.5", pw),
        ("pwsh", '$cred = ConvertTo-SecureString "{v}" -AsPlainText -Force', pw),
        ("cli-flag", "vault login --token={v}", g.s(B62, 28)),
        ("netrc", "machine api.example.org login ci password {v}", g.s(B62, 24)),
        ("npmrc", "//registry.npmjs.org/:_authToken={v}", "np" + "m_" + g.s(B62, 36)),
        ("docker-auth", '{{"auths": {{"registry.example.org": {{"auth": "{v}"}}}}}}',
         base64.b64encode(("ci:" + g.s(B62, 24)).encode()).decode()),
        ("kubeconfig-token", "users:\n- name: admin\n  user:\n    token: {v}\n", g.s(B62, 48)),
        ("k8s-secret-data", "apiVersion: v1\nkind: Secret\ndata:\n  DB_PASS: {v}\n",
         base64.b64encode(g.password(16).encode()).decode()),
        ("wg-conf", "[Interface]\nPrivateKey = {v}\nAddress = 10.8.0.2/24\n", g.b64(32)),
        ("azure-storage", "DefaultEndpointsProtocol=https;AccountName=stprod;AccountKey={v};"
         "EndpointSuffix=core.windows.net", g.b64(64)),
        ("proxmox", "Authorization: PVEAPIToken=root@pam!ci={v}", g.uuid()),
        ("helm-set", "helm upgrade app ./chart --set db.password={v}", pw),
        ("docker-env", "docker run -e POSTGRES_PASSWORD={v} postgres:16", pw),
        ("ansible", "ansible_become_password: {v}", pw),
        ("tf", 'client_secret = "{v}"', g.s(B62 + "~._-", 40)),
        # admin commands and config files
        ("shadow", "root:{v}:19800:0:99999:7:::", "$6$" + g.s(B62 + "./", 16) + "$" + g.s(B62 + "./", 86)),
        ("htpasswd", "admin:{v}", "$apr1$" + g.s(B62 + "./", 8) + "$" + g.s(B62 + "./", 22)),
        ("bcrypt", "password_hash: {v}", "$2y$12$" + g.s(B62 + "./", 53)),
        ("cisco-secret", "enable secret 9 {v}", "$9$" + g.s(B62 + "./", 14) + "$" + g.s(B62 + "./", 43)),
        ("cisco-type7", "username admin privilege 15 password 7 {v}", g.s("0123456789ABCDEF", 18)),
        ("fortigate", "config system admin\n    edit admin\n        set password ENC {v}\n", "SH2" + g.s(B64, 60)),
        ("net-user", "net user svc_backup {v} /add", pw),
        ("sql-create", "CREATE USER app IDENTIFIED BY '{v}';", pw),
        ("sql-alter", "ALTER USER postgres WITH PASSWORD '{v}';", pw),
        ("pgpassword", "PGPASSWORD={v} psql -h db01 -U app crm", pw),
        ("redis-requirepass", "requirepass {v}", g.s(B62, 24)),
        ("redis-auth", "redis-cli -a {v} ping", g.s(B62, 24)),
        ("mongodb-uri", "mongodb+srv://app:{v}@cluster0.abcde.mongodb.net/prod", g.s(B62, 20)),
        ("jdbc", "jdbc:mysql://db01:3306/crm?user=app&password={v}&useSSL=true", g.s(B62, 18)),
        ("ldapsearch", "ldapsearch -x -H ldaps://dc01 -D cn=svc,dc=corp -w {v} -b dc=corp", g.s(B62, 18)),
        ("openssl-pass", "openssl pkcs12 -export -out cert.pfx -inkey key.pem -in cert.pem -passout pass:{v}", pw),
        ("docker-login", "docker login -u ci -p {v} registry.example.org", g.s(B62, 32)),
        ("kubectl-literal", "kubectl create secret generic db --from-literal=password={v}", pw),
        ("smbclient", "smbclient //fs01/share -U backup%{v}", pw),
        ("mount-cifs", "mount -t cifs //fs01/share /mnt -o username=backup,password={v},vers=3.0", pw),
        ("cifs-cred", "username=backup\npassword={v}\ndomain=CORP\n", pw),
        ("xfreerdp", "xfreerdp /v:ts01 /u:admin /p:{v} /cert:ignore", pw),
        ("plink", "plink -ssh root@10.0.0.5 -pw {v} uptime", pw),
        ("psexec", "psexec \\\\srv01 -u CORP\\admin -p {v} cmd", pw),
        ("wget", "wget --user=ci --password={v} https://files.example.org/a.zip", pw),
        ("aws-credentials", "[default]\naws_access_key_id = AK" + "IA" + g.s(UPNUM, 16) +
         "\naws_secret_access_key = {v}\n", g.s(B64, 40)),
        ("pip-conf", "[global]\nindex-url = https://__token__:{v}@pypi.example.org/simple", g.s(B62, 32)),
        ("git-remote", "origin  https://oauth2:{v}@gitlab.example.org/group/app.git (fetch)", g.s(B62 + "-_", 26)),
        ("rclone", "[s3]\ntype = s3\naccess_key_id = AK" + "IA" + g.s(UPNUM, 16) + "\nsecret_access_key = {v}\n",
         g.s(B64, 40)),
        ("wpa", 'network={{\n    ssid="Office"\n    psk="{v}"\n}}', pw),
        ("compose-env", "services:\n  db:\n    image: postgres:16\n    environment:\n      - POSTGRES_PASSWORD={v}\n", pw),
        ("k8s-stringdata", "kind: Secret\nstringData:\n  password: {v}\n", pw),
        ("gh-actions-log", "Run curl -H 'PRIVATE-TOKEN: {v}' https://gitlab.example.org/api/v4/projects", g.s(B62 + "-_", 26)),
        ("powershell-param", "Invoke-Sqlcmd -ServerInstance sql01 -Username sa -Password '{v}' -Query 'SELECT 1'", pw),
        ("new-localuser", '$pw = ConvertTo-SecureString -String "{v}" -AsPlainText -Force', pw),
        ("pw-alone", "{v}", g.password(20)),
        ("pw-alone-12", "{v}", g.password(12)),
        ("token-alone-20", "{v}", g.s(B62, 20)),
        ("token-alone-prefix", "{v}", "tok_" + g.s(B62, 18)),
        ("kubeconfig-client-key", "users:\n- name: admin\n  user:\n    client-key-data: {v}\n",
         base64.b64encode(("-----BEGIN " + "EC PRIVATE KEY-----\n" + g.b64(90) + "\n-----END " +
                           "EC PRIVATE KEY-----\n").encode()).decode()),
    ]
    for name, tpl, v in ctx:
        out.append(("ctx-" + name, tpl.format(v=v), v))
    out += _jwt_cases(g)
    return out


def _b64json(obj) -> str:
    import json
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def _jwt_cases(g: Gen) -> list[tuple[str, str, str]]:
    """JWTs as code and docs carry them: split at the dots, only the payload, unsigned."""
    head = _b64json({"alg": "HS256", "typ": "JWT"})
    payload = _b64json({"sub": g.s(LOWNUM, 8), "company": "Kölpertechnis GmbH", "exp": 1893456789})
    sig = g.b64(32, urlsafe=True, pad=False)
    split = f'# JWT für Testzwecke\njwt_token = (\n    "{head}."\n    "{payload}."\n    "{sig}"\n)\n'
    words_sig = f'jwt_token = (\n    "{head}."\n    "{payload}."\n    "test-signature-not-real"\n)\n'
    return [
        ("jwt-split-at-dots/payload", split, payload),
        ("jwt-split-at-dots/signature", split, sig),
        ("jwt-split-word-signature/payload", words_sig, payload),
        ("jwt-payload-alone", f"payload: {payload}", payload),
        ("jwt-unsigned", f"token={head}.{payload}.", payload),
        ("jwt-bearer-split", f'headers = {{"Authorization": "Bearer {head}." +\n    "{payload}.{sig}"}}', payload),
    ]


NEGATIVES: list[tuple[str, str]] = [
    ("prose-de", "Morgen um 10 Uhr besprechen wir die Roadmap für Q4. Bitte die Folien bis heute Abend "
     "hochladen; die Präsentation liegt im Teams-Kanal unter Projekte/Allgemein."),
    ("prose-en", "The deployment failed because the readiness probe timed out after 30 seconds. "
     "Increase initialDelaySeconds or check the database connection pool settings."),
    ("identifiers", "AbstractSingletonProxyFactoryBean InternalFrameTitlePaneMaximizeButtonWindowNotFocusedState "
     "test_watcher_offers_revert_for_pseudonymised_result getElementsByTagNameNS "
     "HTMLTableSectionElement XMLHttpRequestEventTarget ContainerRegistryPasswordCredentials"),
    ("java-fqn", "at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory"
     ".createBean(AbstractAutowireCapableBeanFactory.java:517)\n"
     "at com.fasterxml.jackson.databind.deser.BeanDeserializer.deserializeFromObject(BeanDeserializer.java:340)"),
    ("python-tb", 'Traceback (most recent call last):\n  File "/usr/lib/python3.11/site-packages/requests/'
     'adapters.py", line 486, in send\n    resp = conn.urlopen(\nurllib3.exceptions.MaxRetryError: '
     "HTTPSConnectionPool(host='api.github.com', port=443): Max retries exceeded"),
    ("k8s-pods", "NAME                                      READY   STATUS    RESTARTS   AGE\n"
     "web-frontend-7d4b9c8f6d-x2lqp             1/1     Running   0          3d4h\n"
     "coredns-5d78c9869d-8kz2m                   1/1     Running   2          41d\n"
     "cert-manager-cainjector-6cc9b5f678-zq7vn   1/1     Running   0          12d\n"),
    ("k8s-manifest", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec:\n  template:\n"
     "    spec:\n      containers:\n      - name: api\n        image: ghcr.io/example/api@sha256:"
     "3f1c9a7e5b2d8c4f6a0e9b7d5c3a1f8e6d4b2c0a9f7e5d3b1c9a7e5b3d1f9c7a\n        env:\n"
     "        - name: DB_PASSWORD\n          valueFrom:\n            secretKeyRef:\n              name: db-secret\n"
     "              key: password\n"),
    ("git-log", "commit 9fceb02d0ae598e95dc970b74767f19372d61af8\nAuthor: Dev <dev@example.org>\n"
     "Date:   Tue Sep 29 17:01:12 2026 +0200\n\n    Fix NER plausibility filter\n"),
    ("docker-ps", "CONTAINER ID   IMAGE          COMMAND                  CREATED\n"
     "4c01db0b339c   postgres:16    \"docker-entrypoint.s…\"   2 hours ago\n"),
    ("pip-freeze", "PySide6==6.7.2\nPyYAML==6.0.1\ncryptography==43.0.0\nsecretstorage==3.3.3\n"
     "keyring==25.2.1\nrequests-toolbelt==1.0.0\n"),
    ("sri", '<script src="https://cdn.example.org/lib.min.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K'
     '/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>'),
    ("npm-lock", '"node_modules/lodash": {\n  "version": "4.17.21",\n  "resolved": "https://registry.npmjs.org/'
     'lodash/-/lodash-4.17.21.tgz",\n  "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVx'
     'VjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="\n}'),
    ("paths", r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.21.2361.0_x64__8wekyb3d8bbwe\wt.exe"
     "\n/usr/share/icons/hicolor/scalable/apps/org.gnome.Settings.DarkModeSwitcher.svg\n"
     "/var/lib/rancher/rke2/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1234/fs"),
    ("urls", "https://github.com/it-an-der-bar/ClipCloak/actions/runs/11122334455/job/31234567890\n"
     "https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow\n"
     "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLbpi6ZahtOH6Blw3RGYpWkSByi_T7Rygb"),
    ("azure-id", "/subscriptions/6f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0/resourceGroups/rg-prod-weu/providers/"
     "Microsoft.Compute/virtualMachines/vm-app01"),
    ("arn", "arn:aws:iam::123456789012:role/service-role/AWSCodePipelineServiceRole-eu-central-1-deploy"),
    ("uuids", "request 6f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0 correlation 0b4c9d2e-7f3a-4e1b-9c8d-2a6f5e4d3c21"),
    ("ulid", "event id 01ARZ3NDEKTSV4RRFFQ69G5FAV processed"),
    ("versions", "Kernel 6.18.44-fc-v37, glibc 2.36-9+deb12u7, python3-pyside6.qtwidgets 6.4.2-4, "
     "linux-image-6.1.0-25-amd64, v0.1.30-rc.2+build.20260929"),
    ("config-no-secret", "password_min_length: 12\npassword_policy: strong\ntoken_ttl: 3600\n"
     "secret_name: db-credentials\napi_url: https://api.example.org\nauth: oidc\n"),
    ("placeholders", "password: ${DB_PASSWORD}\ntoken: <your-token-here>\napi_key: changeme\n"
     "secret: '{{ vault_secret }}'\nPASSWORD=****\n"),
    ("css", ".MuiButtonBase-root-MuiIconButton-root .css-1d3bbye-MuiTypography-root { color: #1976d2; }"),
    ("i18n-keys", "settings.offer_revert settings.watch_mode popup.b64_decode_pseudo wb.b64_encode_sel "
     "log.watch_pseudonymised"),
    ("long-words", "Donaudampfschifffahrtsgesellschaftskapitän Rindfleischetikettierungsüberwachungsaufgaben"
     "übertragungsgesetz Grundstücksverkehrsgenehmigungszuständigkeitsübertragungsverordnung"),
    ("snake-const", "MAX_CONCURRENT_BACKGROUND_JOBS_PER_WORKER DEFAULT_KUBERNETES_SERVICE_ACCOUNT_NAMESPACE"),
    ("windows-ids", "KB5034441 {4D36E972-E325-11CE-BFC1-08002BE10318} "
     "Microsoft.Windows.ShellExperienceHost_10.0.19041.3636_neutral_neutral_cw5n1h2txyewy"),
    ("hostnames", "srv-dc01.corp.example.org pve-node-03.lab.example.net ip-10-0-12-34.eu-central-1.compute.internal"),
    ("base64-image", "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="),
    ("stripe-object-ids", "Customer cus_NffrFeUfNV2Hib paid invoice in_1MtHbELkdIwHu7ixl4OzzPMv"),
    ("request-ids", "requestId=req_011CfXgMam6bUwon1XQdg4M9 traceparent=00-4bf92f3577b34da6a3ce929d0e0e4736-"
     "00f067aa0ba902b7-01"),
    ("docs-ids", "https://docs.google.com/spreadsheets/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit#gid=0"),
    ("mixed-code", "def _balanced_len(val: str) -> int:\n    depth = 0\n    for i, ch in enumerate(val):\n"
     "        if ch in \"([{\":\n            depth += 1\n    return len(val)\n"),
    ("sql", "SELECT u.id, u.username, u.password_hash FROM users u WHERE u.last_login > NOW() - INTERVAL '30 days';"),
    ("hash-output", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  clipcloak-v0.1.30.tar.gz"),
    ("pgp-fingerprint", "Key fingerprint = 4AEE 18F8 3AFD EB23 1234 5678 9ABC DEF0 1234 5678"),
    ("ssh-fp", "ED25519 key fingerprint is SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s."),
    ("ssh-pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl dev@laptop"),
    ("cert-b64", "certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJkekNDQVIyZ0F3SUJBZ0l"
     "CQURBS0JnZ3Foa2pPUFFRREFqQWpNU0V3SHdZRFZRUUREQmhyTTNNdGMyVnlkbVZ5TFdOaEFBQUFBQUFBQQo="),
]


NEGATIVES += [
    ("nginx", "server {\n    listen 443 ssl http2;\n    server_name portal.example.org;\n"
     "    ssl_certificate /etc/letsencrypt/live/portal/fullchain.pem;\n"
     "    ssl_certificate_key /etc/letsencrypt/live/portal/privkey.pem;\n"
     "    location / { proxy_pass http://127.0.0.1:8080; proxy_set_header Host $host; }\n}\n"),
    ("systemd", "[Unit]\nDescription=ClipCloak sync\nAfter=network-online.target\n\n[Service]\n"
     "ExecStart=/usr/local/bin/sync --config /etc/sync.yaml\nEnvironmentFile=/etc/default/sync\n"
     "Restart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n"),
    ("gh-actions", "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
     "      - run: gh release upload ${{ github.ref_name }} dist/*\n        env:\n"
     "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n          SIGN_PASSWORD: ${{ secrets.SIGN_PASSWORD }}\n"),
    ("ansible", "- name: create db user\n  community.postgresql.postgresql_user:\n    name: app\n"
     "    password: \"{{ vault_db_password }}\"\n    login_password: \"{{ postgres_admin_password }}\"\n"),
    ("terraform", 'resource "azurerm_mssql_server" "sql" {\n  administrator_login          = "sqladmin"\n'
     "  administrator_login_password = var.sql_admin_password\n  version = \"12.0\"\n}\n"),
    ("helm-values", "postgresql:\n  auth:\n    existingSecret: db-credentials\n    secretKeys:\n"
     "      adminPasswordKey: postgres-password\n      userPasswordKey: password\n"),
    ("env-example", "DB_HOST=localhost\nDB_USER=app\nDB_PASSWORD=\nAPI_TOKEN=<your-token-here>\n"
     "SECRET_KEY=changeme\n"),
    ("pwsh-prompt", "$cred = Get-Credential -UserName CORP\\admin -Message 'Login'\n"
     "$pw = Read-Host -AsSecureString -Prompt 'Password'\nNew-LocalUser -Name svc -Password $pw\n"),
    ("cisco-no-secret", "service password-encryption\nno ip http server\nip ssh version 2\n"
     "username admin privilege 15 secret\nline vty 0 4\n transport input ssh\n"),
    ("sql-no-secret", "ALTER USER app PASSWORD EXPIRE;\nSELECT usename, passwd IS NOT NULL FROM pg_shadow;\n"),
    ("cli-prompts", "net user admin * /domain\nopenssl pkcs12 -export -passout env:PFX_PASS -out a.pfx\n"
     "ldapsearch -x -W -D cn=admin,dc=corp -b dc=corp\nrunas /user:CORP\\admin cmd\n"
     "echo $TOKEN | docker login --password-stdin -u ci registry.example.org\n"),
    ("syslog", "Sep 29 17:02:11 srv01 sshd[2211]: Accepted publickey for root from 10.0.0.5 port 50022 ssh2: "
     "ED25519 SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s\n"
     "Sep 29 17:02:11 srv01 systemd-logind[811]: New session 4711 of user root.\n"),
    ("go-sum", "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n"
     "github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=\n"),
    ("pip-hashes", "requests==2.32.3 \\\n    --hash=sha256:70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6\n"),
    ("api-json", '{"id": "01J8ZQ4Q6W2V9Y3N5T7R1K0M2P", "etag": "W/\\"3f1c9a7e\\"", "status": "active", '
     '"created_at": "2026-09-29T15:02:11Z", "owner": {"login": "it-an-der-bar", "node_id": "MDQ6VXNlcjE="}}'),
    ("k8s-events", "LAST SEEN   TYPE     REASON    OBJECT                          MESSAGE\n"
     "2m          Normal   Pulled    pod/api-7d4b9c8f6d-x2lqp        Successfully pulled image \"ghcr.io/"
     "example/api:v1.4.2\" in 1.2s\n"),
    ("mail", "Hallo Herr Hartmann,\n\nanbei wie besprochen das Angebot. Das Passwort für das PDF schicke ich "
     "Ihnen separat per SMS.\n\nMit freundlichen Grüßen\nMax Mustermann\nTel. +49 561 1234567\n"),
]


# values that look technical but are no secret – in every wrapper except "alone" (a lone value in the
# clipboard is treated as a password / token on purpose), "sentence" ("Token: …" says it is one) and
# "url-hook" (a random value after /hooks/ is the webhook secret)
NEG_VALUES = [
    "AbstractSingletonProxyFactoryBean", "test_watcher_offers_revert_for_pseudonymised_result",
    "cert-manager-cainjector-6cc9b5f678-zq7vn", "6f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0", "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "/usr/share/icons/hicolor/scalable/apps/org.gnome.Settings.svg", "org.springframework.beans.factory.support",
    "python3-pyside6.qtwidgets", "v0.1.30-rc.2+build.20260929", "MAX_CONCURRENT_BACKGROUND_JOBS_PER_WORKER",
    "Donaudampfschifffahrtsgesellschaft", "srv-dc01.corp.example.org", "req_011CfXgMam6bUwon1XQdg4M9",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "ContainerRegistryPasswordCredentials", "getElementsByTagNameNS",
    "ghcr.io/example/api:v1.4.2", "Microsoft.WindowsTerminal_8wekyb3d8bbwe", "2026-09-29T17:02:11.123456Z",
    "sha256:3f1c9a7e5b2d8c4f6a0e9b7d5c3a1f8e6d4b2c0a9f7e5d3b1c9a7e5b3d1f9c7a",
]


def negatives() -> list[tuple[str, str]]:
    out = list(NEGATIVES)
    for v in NEG_VALUES:
        for wname, wrap in WRAPPERS:
            if not wname.startswith("alone") and wname not in ("sentence", "url-hook"):
                out.append((f"value:{v[:24]}/{wname}", wrap(v)))
    return out
