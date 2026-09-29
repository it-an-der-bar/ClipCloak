"""Shared test helpers."""

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="cc-test-")
# isolate config/data of the tests from the real user profile
for _suffix in ("CONFIG_DIR", "DATA_DIR"):
    from clipcloak.meta import APP_NAME as _N
    os.environ.setdefault(_N.upper().replace("-", "_") + "_" + _suffix, os.path.join(_TMP, _suffix.lower()))

# Fake credentials, assembled at run time so that no token-shaped literal is in the sources
# (secret scanners such as GitHub push protection would block the push).
GLPAT = "gl" + "pat-abcdefghijklmnopqrst1234"
JWT = "ey" + "JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuv"
PEM_HEAD, PEM_TAIL = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----"

SAMPLE = r"""Hallo Team, Jonas Hartmann (jonas.hartmann@contoso.com) hat srv-dc01.contoso.local (10.88.10.10/24, GW 10.88.10.1) neu aufgesetzt.
Öffentlich: 85.10.20.30, IPv6 2a01:4f8:1:2::abcd, Netz 10.88.0.0/16, Maske 255.255.255.0, Version 1.2.3.4
MAC 00:1A:2B:3C:4D:5E, Tel. +49 561 1234567 oder 0561/123456
IBAN DE89 3704 0044 0532 0130 00, Karte 4111 1111 1111 1111
Pfad C:\Users\mhartmann\Documents und /home/jhartmann/.ssh, Account CONTOSO\mhartmann, SID S-1-5-21-1004336348-1177238915-682003330-1105
jhartmann@srv01:~$ ssh admin@10.88.10.20
token: {GLPAT}
export DB_PASSWORD="S3cr3t!Pass"
curl -u jhartmann:hunter22 https://git.contoso.com/api
postgres://app:dbpass99@db.contoso.local:5432/app
Authorization: Bearer {JWT}
""".replace("{GLPAT}", GLPAT).replace("{JWT}", JWT)
