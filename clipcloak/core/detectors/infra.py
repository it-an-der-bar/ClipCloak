"""Names of infrastructure objects: Kubernetes/Helm/ArgoCD/Compose names, namespaces, releases.

In ``name: kunde-mueller-web`` or ``namespace: acme-prod`` the customer-specific part
("mueller", "acme") is what gives the setup away, while "web", "prod", "scheduler" or a
product name such as "bunkerweb" or "redis" is useful context and not secret.

1. Collect values from typical keys (name, namespace, instance, release, app, …), from
   ``-n/--namespace``, ``kind/name`` references and ArgoCD tracking ids.
2. Split them into parts at ``- _ .`` and keep generic words, product names, the user's
   generic labels and allow list; the remaining parts are the sensitive words.
3. Report every whole-word occurrence of those words anywhere in the text, so
   ``scheduler-acme-front``, ``acme-front:apps/Deployment:acme-front/…`` and the
   namespace all get the same pseudonym (shared word map with domains).
"""

from __future__ import annotations

import re

from .. import wordlists
from ..entities import EntityType as T
from . import shellctx
from .base import Detector

KEYS = {
    "name", "namespace", "instance", "release", "releasename", "release_name", "release-name",
    "app", "appname", "app_name", "application", "service", "servicename", "service_name",
    "secretname", "secret_name", "claimname", "configmap", "configmapname", "container_name",
    "containername", "cluster", "clustername", "cluster_name", "project", "projectname",
    "project_name", "tenant", "customer", "fullnameoverride", "nameoverride", "part-of",
    "k8s-app", "serviceaccountname", "serviceaccount", "service_account", "deployment",
    "statefulset", "daemonset", "database", "dbname", "db_name", "stack", "stackname",
    "compose_project_name", "hostname", "release-namespace", "targetrevision_name",
}
LINE_RE = re.compile(
    r"""(?m)^[ \t]*(?:-[ \t]+)?["']?(?P<key>[A-Za-z0-9_.\-/]{1,120})["']?[ \t]*[:=][ \t]*"""
    r"""["']?(?P<val>[A-Za-z0-9][A-Za-z0-9_.\-]{1,252})["']?[ \t]*,?[ \t]*(?:\#.*)?$""")
NS_RE = re.compile(r"(?:^|\s)(?:-n|--namespace)[ =]([a-z0-9][a-z0-9-]{1,62})(?![\w-])")
REF_RE = re.compile(
    r"(?:^|\s)(?:deploy|deployment|deployments|sts|statefulset|statefulsets|ds|daemonset|svc|service|"
    r"services|po|pod|pods|cm|configmap|secret|secrets|ing|ingress|job|cronjob|pvc|ns|namespace|"
    r"helmrelease|application|app)"
    # optional API group as in kubectl output: deployment.apps/x, helmrelease.helm.toolkit.fluxcd.io/x
    r"(?:\.(?:apps|batch|extensions|policy|autoscaling|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:k8s\.io|argoproj\.io|fluxcd\.io)))?"
    r"/([a-z0-9][a-z0-9.-]{1,252})(?![\w/-])", re.IGNORECASE)
FILE_NAME = re.compile(r"\.(?:sh|bash|ps1|py|js|ts|go|rb|pl|php|ya?ml|json|toml|ini|conf|cfg|env|txt|md|log|"
                       r"xml|html?|css|csv|tar|gz|tgz|zip|sql|j2|tpl|tmpl|lock|pem|crt|key|bak|service)$", re.IGNORECASE)
TRACKING_RE = re.compile(
    r"(?<![\w.-])([a-z0-9][a-z0-9.-]*):[a-z0-9.]*/[A-Za-z]+:([a-z0-9][a-z0-9.-]*)/([a-z0-9][a-z0-9.-]*)")
PART_RE = re.compile(r"[^\-_.]+")
WORD_RE = re.compile(r"^([A-Za-zÄÖÜäöüß]{3,})(\d*)$")
SKIP_VALUES = {"true", "false", "yes", "no", "on", "off", "null", "none", "always", "never",
               "ifnotpresent", "recreate", "rollingupdate", "clusterip", "nodeport", "loadbalancer",
               "tcp", "udp", "http", "https", "opaque", "retain", "delete", "readwriteonce"}


class InfraNameDetector(Detector):
    id = "infra-names"
    types = (T.IDENTIFIER.value,)
    priority = 35

    def _keep(self, ctx) -> set[str]:
        keep = set(wordlists.GENERIC_LABELS) | wordlists.INFRA_GENERIC | wordlists.INFRA_PRODUCTS
        keep |= {w.lower() for w in ctx.options.get("generic_labels", ())}
        keep |= {w.lower() for w in ctx.options.get("allow_terms", ())}
        return keep

    @staticmethod
    def _key_ok(key: str) -> bool:
        k = key.lower()
        return k in KEYS or k.rsplit("/", 1)[-1] in KEYS or k.rsplit(".", 1)[-1] in KEYS

    def _values(self, text: str) -> list[str]:
        vals = []
        for m in LINE_RE.finditer(text):
            if self._key_ok(m.group("key")):
                vals.append(m.group("val"))
        vals += [m.group(1) for m in NS_RE.finditer(text)]
        for m in REF_RE.finditer(text):
            # "sh deploy/compose/start.sh", "cat app/values.yaml": file paths, no kind/name
            if FILE_NAME.search(m.group(1)) or shellctx.first_word(text, m.start(1)) in shellctx.FILE_COMMANDS:
                continue
            vals.append(m.group(1))
        for m in TRACKING_RE.finditer(text):
            vals += [m.group(1), m.group(2), m.group(3)]
        return vals

    def sensitive_words(self, text: str, ctx) -> set[str]:
        keep = self._keep(ctx)
        tlds = wordlists.ALL_TLDS | wordlists.INTERNAL_TLDS | {t.lower() for t in ctx.extra_tlds}
        words: set[str] = set()
        for val in self._values(text):
            low = val.lower()
            if low in SKIP_VALUES or "{{" in val or re.fullmatch(r"v?\d+([.-]\d+)*", low):
                continue
            if "." in low and low.rsplit(".", 1)[-1] in tlds:
                continue                                   # a domain: the domain detector's job
            for part in PART_RE.findall(low):
                m = WORD_RE.match(part)
                if not m:
                    continue                               # hashes, numbers, pod suffixes
                w = m.group(1)
                if w in keep or part in keep:
                    continue
                words.add(w)
        return words

    def find(self, text, ctx):
        words = self.sensitive_words(text, ctx)
        if not words:
            return []
        rx = re.compile(r"(?<![A-Za-z0-9ÄÖÜäöüß])(" + "|".join(sorted(map(re.escape, words), key=len, reverse=True))
                        + r")(?=\d*(?![A-Za-zÄÖÜäöüß]))", re.IGNORECASE)
        # every whole-word occurrence, also in prose ("… bei acme") and in domains
        # (the domain detector wins there and uses the same word map)
        return [self.mk(m.start(1), m.end(1), T.IDENTIFIER.value, text) for m in rx.finditer(text)]
