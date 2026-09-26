# ClipCloak

[English](README.md)

ClipCloak läuft im System-Tray (Windows und Linux) und bereinigt die Zwischenablage, bevor du
sie in einen KI-Chat, ein Ticket oder ein Forum einfügst. Es **schwärzt**, **anonymisiert** oder
**pseudonymisiert umkehrbar** und kann die **Pseudonyme wieder zurückübersetzen**, wenn du die
Antwort kopierst.

```
Vorher   jonas.hartmann@contoso.com  srv-dc01.contoso.local  10.88.10.10/24  GW 10.88.10.1  password: S3cr3t!
Nachher  yara.kirchner@pluwolul.com      srv-dc01.pluwolul.local 10.58.239.119/24 GW 10.58.239.1 password: J0iy9f!
```

## Funktionen

- **Drei Modi**
  - *Pseudonymisieren*: konsistente, formattreue Ersetzungen, die sich umkehren lassen.
  - *Anonymisieren*: realistische, aber irreversible Werte oder Platzhalter `<TYP_n>`.
  - *Schwärzen*: ersetzt jeden Fund durch `[REDACTED]` (konfigurierbar, `{type}` möglich).
- **Logisch passende Ersetzungen**
  - IP-Adressen behalten ihre Klasse. 10/8 bleibt in 10/8, 172.16/12, 192.168/16, CGNAT und Link-Local bleiben in ihren Bereichen, öffentliche Adressen bleiben öffentlich. IPv6 ULA, Link-Local und Global behalten ihre Klasse ebenfalls.
  - Subnetze bleiben erhalten (präfixerhaltend, Crypto-PAn-Prinzip). Hosts desselben /24 (IPv4) bzw. /64 (IPv6) landen im selben Ersatz-Subnetz. `.0/.1/.254/.255` und `::1` bleiben stehen, damit Gateway und Broadcast erkennbar sind. CIDR-Angaben behalten ihre Präfixlänge.
  - Domains behalten Aufbau und TLD. Generische Labels wie `www`, `mail`, `vpn`, `srv` oder `k8s` bleiben. Dasselbe Wort bekommt überall dasselbe Pseudonym: in der Mail-Domain, im Hostnamen, in der NetBIOS-Domäne `CONTOSO\user` und in einem als eigener Begriff hinterlegten Firmennamen.
  - E-Mail-Adressen werden zu plausiblen Personennamen. `jonas.hartmann@` lernt dabei die Namen *Jonas* und *Hartmann*, die dann auch im Fließtext ersetzt werden.
  - Folgendes bleibt formattreu:
    - IBANs bekommen eine gültige Prüfsumme.
    - Kreditkartennummern sind Luhn-gültig.
    - Telefonnummern behalten Ländervorwahl und Schreibweise.
    - MAC-Adressen behalten den Hersteller-OUI (optional).
    - Windows-SIDs behalten die RID und bekommen einen konsistenten Domänenteil.
    - Secrets behalten Länge, Zeichenklassen und bekannte Präfixe (`glpat-`, `ghp_`, JWT-Header …).
  - JSON, YAML, XML, `.env` und Code bleiben syntaktisch gültig, auch bei escapten Strings und PEM-Blöcken in JSON.
- **Zurückübersetzen.** LLM-Antwort kopieren und das Revert-Kürzel drücken, dann stehen die Originalwerte wieder drin. Das klappt auch für:
  - IPs, die das LLM in einem bekannten Ersatz-Subnetz neu erfunden hat (die Abbildung ist eine Bijektion)
  - Wörter, deren Groß-/Kleinschreibung das LLM verändert hat
- **Was erkannt wird**
  - IPv4/IPv6-Adressen und Netze, MAC-Adressen, E-Mail-Adressen, Domains/FQDNs (mit Heuristiken gegen Code wie `logger.info` oder `user.name`), UNC-Hosts und Shell-Prompts (`user@host:~$`)
  - Benutzernamen in `C:\Users\…`, `/home/…` und `DOMAIN\user`, Windows-SIDs, IBANs, Kreditkarten, Telefonnummern
  - Secrets:
    - Token-Formate: GitLab, GitHub, AWS, Slack, OpenAI/Anthropic, Stripe, npm, PyPI, Docker, Vault, HF, JWT, Azure SAS
    - PEM-Private-Keys und -Zertifikate
    - Zugangsdaten als Schlüssel/Wert in JSON, YAML, `.env`, INI, XML und Connection-Strings
    - URL-Credentials, `curl -u`, `mysql -p`, `--password`, `ConvertTo-SecureString`
    - zufällig wirkende Strings (optional)
  - Infrastruktur-Namen: Werte von `name`, `namespace`, `instance`, `release`, `app` …, `-n`/`--namespace`, `deploy/<name>`, ArgoCD-Tracking-IDs. Ersetzt werden nur die kundenspezifischen Teile (`kunde-mueller-prod` → `kunde-kabaukack-prod`); allgemeine Wörter (front, scheduler, prod …) und Produktnamen (bunkerweb, nginx, redis …) bleiben, und dasselbe Wort bekommt überall dasselbe Pseudonym, auch in Domains. Kubernetes-Label-/Annotation-Keys wie `argocd.argoproj.io/tracking-id:` werden nie angefasst.
  - **Ursprungsnachweise in Links** – werden in jedem Modus entfernt, nicht pseudonymisiert: `utm_*`, Klick-IDs (`fbclid`, `gclid`, `msclkid` …), Newsletter-Empfänger-IDs (`mc_eid`, `_hsenc`, `mkt_tok` …), Share-IDs (`si` bei YouTube/Spotify, `igsh`, X `s`/`t`, TikTok, LinkedIn …), Amazon `/ref=…`, Textfragmente `#:~:text=…`. Umleitungen (Outlook Safe Links – enthalten die Adresse des Empfängers –, Google `/url`, Facebook `l.php`, LinkedIn, Slack, YouTube, Steam, DuckDuckGo, Proofpoint URL Defense) werden durch das echte Ziel ersetzt. Eigene Parameter: Einstellungen › Listen › Tracking-Parameter.
  - **eigene Begriffe** (wörtlich oder Regex, mit optionalem Typ oder fester Ersetzung), bekannte Domains und Ausnahmelisten
- **Bilder.** Der Reiter *Bild* verdeckt Gesichter (Mosaik), sensiblen Text wie IP-Adressen, E-Mail-Adressen und Tokens in Screenshots (schwarz) sowie QR-Codes/Barcodes (schwarz). Bereiche lassen sich von Hand ergänzen, verschieben und in der Größe ändern; das Ergebnis ist ein neues, flaches Bild ohne Metadaten. Siehe [Bilder](#bilder).
- **Optionales Plugin.** Ein separates Hilfsprogramm findet Personen- und Firmennamen ohne festes Format (spaCy, deutsches/englisches Modell) sowie Gesichter, Text und Codes in Bildern (OpenCV mit dem YuNet-Gesichtsmodell, RapidOCR). Es läuft komplett lokal, und das Hauptprogramm bleibt schlank.
- **Optionale LLM-Funktionen** (OpenAI-kompatibler Endpunkt, z. B. vLLM, Ollama, LiteLLM):
  - *Screenshot → Text*: Ein Vision-Modell liest ein Bild aus der Zwischenablage aus, der Text wird anschließend verarbeitet.
  - *Prüfung*: Der bereits verarbeitete Text geht ans LLM, das mögliche Reste meldet. Diese lassen sich per Klick als eigene Begriffe übernehmen.
  - *Erkenner*: Das LLM dient als zusätzlicher Namens-/Firmen-Erkenner. Dabei geht der Originaltext an deinen Endpunkt, daher ist das standardmäßig aus.
- **Überwachung der Zwischenablage** mit vier Modi:
  - *aus*
  - *melden*: Ein Popup bietet Pseudonymisieren, Anonymisieren, Schwärzen oder Details an.
  - *kritisch automatisch*: Secrets, Schlüssel, IBAN und Karten werden sofort verarbeitet, der Rest fragt nach.
  - *immer*
- **Werkbank** mit Live-Markierung, Fundtabelle und Rechtsklick-Aktionen (Ausnahme oder eigener Begriff). Beliebigen markierten Text in der Eingabe per Rechtsklick auf *immer ersetzen* oder *nie ersetzen* setzen.
- **Verlauf** mit Vorher/Nachher-Diff jeder Aktion.
- **Zuordnungsübersicht**: was wurde wodurch ersetzt, mit Filter und CSV-Export.
- **Pseudonyme werden verschlüsselt gespeichert.** Standardmäßig landen sie im Projekt *Standard*, damit das Zurückübersetzen auch nach einem Neustart klappt. Unter Windows ist jede Projektdatei mit dem Windows-Konto des Benutzers verschlüsselt (DPAPI, ohne Passphrase); zusätzlich ist eine Projekt-Passphrase möglich (AES-256-GCM, scrypt). Weitere Projekte (z. B. pro Kunde) lassen sich anlegen, jedes mit eigenen Begriffen und bekannten Domains. *Nur RAM* muss man ausdrücklich wählen; es ist als "geht beim Beenden verloren" gekennzeichnet.
- **Zentrale Verwaltung.** MSI für die stille Installation (GPO, ESET PROTECT, baramundi, Intune …), ADMX-Vorlagen für Gruppenrichtlinien, maschinenweite Standard- und Richtliniendateien. Vorgegebene Einstellungen sind in der Oberfläche gesperrt.
- **HTML-Inhalte der Zwischenablage** (Outlook, Teams, Browser) werden mitverarbeitet. RTF wird verworfen, damit keine unbearbeitete Kopie übrig bleibt.
- **Oberfläche** auf Deutsch und Englisch.

## Installation

| Datei | Inhalt |
|---|---|
| `clipcloak-vX.Y.Z-windows-x86_64.msi` | Windows-Installer für alle Benutzer (`C:\Program Files\ClipCloak`), Programm + NER-Plugin; für die Softwareverteilung siehe [Verteilung](#verteilung-windows) |
| `clipcloak-vX.Y.Z-windows-x86_64.zip` | Windows portabel: Ordner mit `clipcloak.exe`, NER-Plugin in `ner\`, ADMX-Vorlagen und Beispiel-Richtliniendateien in `policies\`, README, Lizenz |
| `clipcloak-vX.Y.Z-linux-x86_64.tar.gz` | `clipcloak`, NER-Plugin `clipcloak-ner`, `.desktop`-Datei, Icon, Beispiel-Richtliniendateien, README, Lizenz (mit `tar xzf` entpacken, die Ausführungsrechte bleiben erhalten) |
| `clipcloak-vX.Y.Z-linux-x86_64` | nur das Linux-Programm, ohne NER-Plugin |

ZIP und tar.gz brauchen keine Installation: irgendwohin entpacken und das Programm starten. Den Ordner
zusammenlassen – unter Windows braucht das Programm seinen Ordner `_internal`, das NER-Plugin den Ordner `ner`.
Das NER-Plugin läuft nur, wenn es in den Einstellungen aktiviert ist.

Unter Linux braucht das Binary glibc ≥ 2.36 (Debian 12, Ubuntu 24.04, Fedora 37 oder neuer) und die
üblichen Qt/X11-Bibliotheken. Unter Debian/Ubuntu sind das `libxcb-cursor0 libxkbcommon-x11-0 libegl1`.
Unter Wayland zusätzlich `wl-clipboard` installieren. GNOME braucht für das Tray-Icon die
*AppIndicator*-Erweiterung.

## Bedienung

| Standard-Kürzel | Aktion |
|---|---|
| `Strg+Alt+P` | Zwischenablage pseudonymisieren |
| `Strg+Alt+A` | anonymisieren |
| `Strg+Alt+R` | schwärzen |
| `Strg+Alt+U` | Pseudonyme zurückübersetzen |
| `Strg+Alt+W` | Werkbank öffnen |
| `Strg+Alt+I` | Bild in der Zwischenablage schwärzen (Reiter Bild) |

Die Werkbank hat einen Button pro Aktion. Das Ergebnis landet automatisch in der Zwischenablage;
die Checkbox neben den Buttons (bzw. `general.workbench_auto_copy`) schaltet das ab.

Die Sprache stellst du unter Einstellungen › Allgemein › Sprache / Language ein; danach bietet das Programm einen Neustart an.
Projekte wechselst, legst an und konfigurierst du in der Leiste über den Tabs des Hauptfensters, im Menü *Projekt* oder im Tray.

Alle Kürzel sind einstellbar, und weitere Aktionen lassen sich belegen: Verarbeiten im
Standardmodus, Screenshot → Text, Überwachung ein/aus. Das Tray-Menü enthält alle Aktionen sowie
Standardmodus, Überwachungsmodus, Pause, Projekte, Verlauf, Zuordnungen und Einstellungen.

So läuft ein typischer LLM-Durchgang:

1. Config oder Log kopieren.
2. `Strg+Alt+P` drücken.
3. In den Chat einfügen.
4. Die Antwort kopieren.
5. `Strg+Alt+U` drücken.
6. Die Antwort einfügen; sie enthält jetzt die echten Werte.

### Wayland

Wayland erlaubt Anwendungen keine globalen Tastenkürzel. Lege die folgenden Befehle stattdessen
in den Desktop-Einstellungen an. KDE: *Systemeinstellungen › Kurzbefehle › Eigene Kurzbefehle*.
GNOME: *Einstellungen › Tastatur › Eigene Tastenkombinationen*.

```
clipcloak --action pseudonymize
clipcloak --action anonymize
clipcloak --action redact
clipcloak --action revert
clipcloak --action workbench
clipcloak --action redact_image
```

Der Befehl reicht die Aktion an die laufende Instanz weiter oder startet sie. Mit `wl-clipboard`
funktionieren Lesen und Schreiben überall. Die Überwachung braucht das Data-Control-Protokoll,
das KDE Plasma und wlroots-Compositoren (Sway, Hyprland …) anbieten, GNOME aber nicht.

### Kommandozeile

```
clipcloak                              Tray-Anwendung starten
clipcloak --action AKTION              Aktion an die laufende Instanz senden
clipcloak process [--mode M] [--project P] [--in F] [--out F]
clipcloak revert  --project P [--passphrase-env VAR] [--in F] [--out F]
clipcloak analyze [--in F]             Funde als JSON
clipcloak projects                     Projekte auflisten
```

`process`/`revert` lesen stdin und schreiben stdout. Unter Windows `--in`/`--out` verwenden, weil
das GUI-Build keine Standardeingabe hat. Bei verschlüsselten Projekten kommt die Passphrase aus der
mit `--passphrase-env` angegebenen Umgebungsvariable oder wird interaktiv abgefragt.

## Dateien

*Datei verarbeiten …* (im Tray und im Hauptfenster unter Datei) verarbeitet eine ganze Textdatei im Hintergrund; 1 MB dauert etwa eine Sekunde. Du wählst die Aktion, das Ergebnis wird neben der Quelle gespeichert, z. B. `notizen.pseudo.md`, mit gleicher Kodierung und gleichen Zeilenenden. Zurückübersetzen funktioniert genauso. Die Werkbank kann Dateien ebenfalls laden und speichern.

## Bilder

Ein Bild (Screenshot, Foto) kopieren und `Strg+Alt+I` drücken (*Bild in der Zwischenablage schwärzen*) oder den
Reiter *Bild* verwenden. Auch die Kürzel für Pseudonymisieren/Anonymisieren/Schwärzen öffnen ein Bild aus der
Zwischenablage dort. Mit eingeschalteter Überwachung erscheint beim Kopieren eines Bildes ein Popup *Bild schwärzen*.

1. **Bild:** aus der Zwischenablage oder aus einer Datei.
2. **Erkennen:** das Plugin sucht lokal nach
   - Gesichtern → Mosaik (YuNet-Modell; findet Gesichter ab etwa 10 px, große Bilder werden zusätzlich verkleinert durchsucht),
   - Nacktheit – unbedeckte Brüste, Genitalien, Gesäß → schwarz (NudeNet-Modell; große Bilder werden zusätzlich in Kacheln durchsucht),
   - Text: OCR, danach dieselben Erkennungen wie für Text in der Zwischenablage (IP, E-Mail, Domains, Secrets, eigene Begriffe, NER-Namen …) → schwarze Balken genau über diesen Zeichen,
   - QR-Codes und Barcodes → schwarz.
   Mit der Maus aufziehen fügt Bereiche von Hand hinzu; verschieben, an der Ecke unten rechts in der Größe ändern, *Entf* löscht, Rechtsklick wechselt den Effekt (schwarz, Mosaik, weichzeichnen). `Strg` + Mausrad zoomt.
3. **Ergebnis:** in die Zwischenablage oder als PNG/JPEG-Datei. Es ist ein neues, flaches Bild: die verdeckten Pixel sind weg, Metadaten der Quelle werden nicht übernommen.

Verpixelter oder weichgezeichneter *Text* lässt sich oft zurückrechnen (z. B. mit [Unredacter](https://bishopfox.com/tools/unredacter)), daher werden Text und Codes standardmäßig schwarz verdeckt; Mosaik ist für Gesichter gedacht. Die automatische Erkennung ist eine Hilfe, keine Garantie – das Bild immer prüfen. Ohne Plugin lassen sich Bereiche von Hand aufziehen. Einstellungen › Bilder schaltet Erkennungen und Effekte.

## Plugin (Namen und Bilder)

MSI (Feature *NER*), ZIP (Ordner `ner\`) und tar.gz enthalten das Plugin bereits. Es enthält spaCy mit dem deutschen/englischen Modell, OpenCV mit dem YuNet-Gesichtsmodell und RapidOCR und läuft komplett lokal. Für Bilder ist nichts einzurichten; für Namen:

1. Unter Einstellungen › Plugin (Namen, Bilder) *NER aktivieren* anhaken, *Testen* klicken und mit OK speichern. Der Reiter zeigt an, ob der Helfer gefunden wurde.
2. Beim Linux-Download ohne NER `clipcloak-ner` aus dem tar.gz neben das Programm legen. Der Helfer wird neben dem Programm oder in dessen Unterordner `ner` gefunden; jeder andere Ort lässt sich unter *Helfer-Programm* eintragen.

## LLM

Einstellungen › LLM:

1. URL eintragen, dazu den API-Token, falls der Endpunkt einen verlangt.
2. *Verbindung testen & Modelle laden* klicken; `/v1` wird bei Bedarf automatisch ergänzt.
3. Textmodell und optional Vision-Modell aus den Dropdowns wählen.
4. Die gewünschten Funktionen einschalten.

Screenshot → Text hat einen eigenen Timeout (Standard 180 s, *Timeout Screenshot → Text*), weil Vision-Modelle
oft deutlich länger brauchen als Textanfragen (Standard 60 s). Der Protokoll-Reiter zeigt den Timeout jeder Anfrage.

## Konfiguration und Daten

| | Windows | Linux |
|---|---|---|
| Einstellungen (`config.yaml`) | `%APPDATA%\clipcloak\` | `~/.config/clipcloak/` |
| Projekte, Log | `%LOCALAPPDATA%\clipcloak\` | `~/.local/share/clipcloak/` |
| Maschinenweite Standards / Richtlinie | `%ProgramData%\clipcloak\` | `/etc/clipcloak/` |

Alles lässt sich im Einstellungsdialog ändern. Die YAML-Datei kann auch von Hand bearbeitet werden.
Sie enthält nur, was von den Standardwerten abweicht; fehlende Schlüssel nehmen die Standardwerte.

## Verteilung (Windows)

### Installation per GPO, ESET PROTECT, baramundi, Intune …

Das MSI installiert für alle Benutzer (pro Maschine, ohne Neustart). Per Doppelklick zeigt es einen
Setup-Assistenten: Willkommen, Lizenz und eine Feature-Auswahl, in der NER-Plugin, *Start with Windows*
(Autostart), Desktop-Verknüpfung und Installationsordner gewählt werden. Still trifft man dieselbe Auswahl
über Eigenschaften oder `ADDLOCAL`:

```
msiexec /i clipcloak-vX.Y.Z-windows-x86_64.msi /qn
msiexec /i clipcloak-vX.Y.Z-windows-x86_64.msi /qn AUTOSTART=0 DESKTOPSHORTCUT=1
msiexec /i clipcloak-vX.Y.Z-windows-x86_64.msi /qn ADDLOCAL=Main,Autostart   (ohne NER-Plugin)
msiexec /x clipcloak-vX.Y.Z-windows-x86_64.msi /qn                           (deinstallieren)
```

| Feature | Bedeutung | Standard | Still |
|---|---|---|---|
| `Main` | Programm, Startmenü-Eintrag | immer | – |
| `NER` | NER-Plugin | an | in `ADDLOCAL` weglassen |
| `Autostart` | bei jeder Anmeldung für alle Benutzer starten (HKLM `…\Run`) | an | `AUTOSTART=0` schaltet ab |
| `DesktopShortcut` | Verknüpfung auf dem gemeinsamen Desktop | aus | `DESKTOPSHORTCUT=1` schaltet ein |

Die Auswahl lässt sich später unter *Einstellungen › Apps* (Ändern) anpassen. Der Assistent ist englisch.

- **Gruppenrichtlinie:** *Computerkonfiguration › Richtlinien › Softwareeinstellungen › Softwareinstallation*, Paket von einer Netzwerkfreigabe (zugewiesen).
- **ESET PROTECT:** Client-Task *Software Install* › *Install by direct package URL* (Bezeichnungen der englischen Oberfläche) (`http://…/…msi` oder `file://\\server\freigabe\…msi`). Der Task installiert MSI-Pakete immer still; msiexec-Schalter lassen sich dort nicht setzen, nur die Eigenschaften des Pakets, z. B. `AUTOSTART=0`.
- **baramundi Management Suite:** Anwendung aus dem MSI (oder mit der Kommandozeile oben) anlegen und per Job zuweisen; zur Erkennung der installierten Version das MSI-Produkt (Upgrade-Code unten) oder den Registry-Wert `HKLM\SOFTWARE\it-an-der-bar\ClipCloak\Version` verwenden.
- **Updates:** das neuere MSI genauso installieren; es ersetzt die alte Version (Major Upgrade, Upgrade-Code `{F6A0337E-BD8E-448C-AEFF-A1E4D06678B7}`) und übernimmt die Feature-Auswahl der installierten Version (ab 0.1.10; `ADDLOCAL`/`REMOVE` auf der Kommandozeile haben Vorrang).
- Benutzereinstellungen, Projekte und Logs bleiben in den Benutzerprofilen; die Deinstallation löscht sie nicht.
- Der Windows-Build ist ein Ordner-Build: beim Start wird nichts nach `%TEMP%` entpackt, das passt zu AppLocker und Endpoint-Schutz. Hat die CI ein Code-Signing-Zertifikat (Variablen `SIGN_PFX_BASE64`, `SIGN_PFX_PASSWORD`), werden Programme und MSI signiert.

### Zentrale Einstellungen

Zwei Ebenen, jeweils aus Dateien und/oder der Registry:

- **Standards** – der Benutzer kann sie ändern: `%ProgramData%\clipcloak\defaults.yaml` (Linux `/etc/clipcloak/defaults.yaml`) oder Registry-Werte unter `HKLM\SOFTWARE\Policies\it-an-der-bar\ClipCloak\Recommended`.
- **Richtlinie** – vorgegeben, in der Oberfläche ausgegraut mit dem Hinweis "Vom Administrator verwaltet": `%ProgramData%\clipcloak\policy.yaml` (Linux `/etc/clipcloak/policy.yaml`), Registry `HKCU\…` oder `HKLM\SOFTWARE\Policies\it-an-der-bar\ClipCloak` (HKLM gewinnt).

Die YAML-Dateien haben den Aufbau von `config.yaml`; Beispiele liegen im ZIP unter `policies\examples\`
(im tar.gz unter `examples/`). Registry-Werte heißen wie die Einstellung, z. B. `watcher.mode` (REG_SZ `critical`),
`ner.enabled` (DWORD `1`), `llm.base_url`. Listen sind ein Unterschlüssel dieses Namens mit den Werten `1`, `2`, …
oder REG_MULTI_SZ; eigene Begriffe als `Begriff` oder `Begriff|TYP|Ersatz` – siehe `policy-example.reg`.

Richtlinien-Einträge unter `lists` (eigene Begriffe, bekannte Domains, Erlaubt-Listen) **ergänzen** die eigenen
Einträge der Benutzer und sind immer aktiv – z. B. um allen die Firmen- und Domainnamen mitzugeben.

**Gruppenrichtlinien-Vorlagen:** `policies\clipcloak.admx` und die Ordner `en-US`/`de-DE` aus dem ZIP in den
Central Store (`\\<Domäne>\SYSVOL\<Domäne>\Policies\PolicyDefinitions`) oder nach `C:\Windows\PolicyDefinitions`
kopieren. Die Einstellungen stehen dann unter *Computer-/Benutzerkonfiguration › Richtlinien › Administrative
Vorlagen › ClipCloak*. Mit ESET oder baramundi ohne GPO stattdessen `policy.yaml` nach `%ProgramData%\clipcloak\`
oder die Registry-Werte verteilen.

Beim Start zeigt der Protokoll-Reiter, welche zentralen Einstellungen geladen wurden, und nennt unbekannte
Schlüssel oder ungültige Werte.

## Sicherheitshinweise

- Die Erkennung ist heuristisch. Prüfe das Ergebnis (Werkbank/Diff), bevor du Sensibles teilst. Für Namen ohne festes Format helfen eigene Begriffe, bekannte Domains, das NER-Plugin oder die LLM-Prüfung.
- Sitzungs-Zuordnungen und Verlauf liegen nur im RAM. Projekte speichern die Zuordnungen samt Originalwerten und Secrets auf der Platte:
  - Windows: immer verschlüsselt (AES-256-GCM). Den Schlüssel schützt DPAPI, gebunden an das Windows-Konto des Benutzers; andere Benutzer, Plattenkopien oder Backups können die Datei nicht lesen. Ältere unverschlüsselte Projektdateien werden beim Öffnen umgestellt. (Abschaltbar unter Einstellungen › Allgemein; nicht empfohlen.)
  - Mit Projekt-Passphrase (alle Systeme) kommt der Schlüssel stattdessen aus der Passphrase (scrypt); das schützt auch vor anderen Programmen unter demselben Konto.
  - Linux ohne Passphrase: lesbares JSON mit Rechten 0600 – die Projektleiste zeigt "NICHT verschlüsselt".
  - Der Projekt*name* bleibt in der Datei lesbar.
- Per Richtlinie gesetzte LLM-Token liegen in der Registry bzw. Richtliniendatei und sind für die Benutzer lesbar.
- Anonymisierte Werte werden nie in eine Zuordnungsdatei geschrieben. Für Platzhalter werden nur schlüsselabhängige Hashes im RAM gehalten.
- Inhalte der Zwischenablage landen nie im Log.
- *Originaltext im Verlauf behalten* lässt sich abschalten. Der Verlauf zeigt die Originale dann nur maskiert.
- Die LLM-Prüfung sendet nur den bereits verarbeiteten Text. Screenshot → Text sendet das Bild. Der LLM-Erkenner sendet den Originaltext; aktiviere ihn daher nur für einen Endpunkt unter deiner Kontrolle.

## Entwicklung

```
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m clipcloak                    # aus dem Quellcode starten
QT_QPA_PLATFORM=offscreen python -m unittest discover -s tests -p "test_*.py" -v
```

Für das Plugin aus dem Quellcode `pip install -r requirements-ner.txt` und
`pip install --no-deps -r requirements-ner-nodeps.txt` ausführen; es wird dann
automatisch über `python -m clipcloak.ner_helper` genutzt. Zum Bauen der Binaries siehe
`.gitlab-ci.yml`; `python tools/package_release.py vX.Y.Z --dist dist` packt sie in ZIP und tar.gz. Die CI testet bei jedem Push und baut und veröffentlicht bei Tags `vX.Y.Z`, die
zur Version in `clipcloak/__init__.py` passen müssen.

### Umbenennen

Der Name ist zentral in `clipcloak/meta.py` festgelegt. `python tools/rename_app.py <neuername> [Anzeigename]`
benennt Paket, Startskripte, CI-Variablen und Doku in einem Schritt um.

## Lizenz

GPL-3.0-only, siehe [LICENSE](LICENSE). Qt for Python (PySide6) wird unter der LGPL-3.0 genutzt.
Plugin: spaCy und seine Modelle, das YuNet-Gesichtsmodell und ONNX Runtime stehen unter der MIT-Lizenz; OpenCV, RapidOCR und die PP-OCR-Modelle unter Apache-2.0. NudeNet liefert den AGPL-3.0-Lizenztext mit (die Paket-Metadaten nennen MIT); Abschnitt 13 der GPL-3.0 erlaubt die Kombination mit diesem GPL-3.0-Programm.
