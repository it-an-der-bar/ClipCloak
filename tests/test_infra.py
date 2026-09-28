"""Kubernetes/Helm/ArgoCD: label keys stay, customer-specific name parts are pseudonymised."""

import unittest

from clipcloak.config import Config, engine_settings
from clipcloak.core.engine import Engine
from clipcloak.core.vault import Vault

K8S = """metadata:
  annotations:
    argocd.argoproj.io/tracking-id: >-
      bunkerweb-front:apps/Deployment:acme-front-instance/scheduler-bunkerweb-front
    cert-manager.io/cluster-issuer: letsencrypt
  labels:
    app.kubernetes.io/instance: bunkerweb-front
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: bunkerweb
    helm.sh/chart: bunkerweb-1.0.10
  name: scheduler-bunkerweb-front
  namespace: acme-front-instance
spec:
  selector:
    matchLabels:
      app.kubernetes.io/instance: bunkerweb-front
---
metadata:
  name: kunde-mueller-web
  namespace: acme-prod
spec:
  containers:
    - name: acme-shop-7d9f8b6c5-xk2lp
      image: registry.acme.de/shop:1.2
kubectl -n acme-prod rollout restart deploy/acme-shop
kubectl get pods -l app.kubernetes.io/name=shop
"""


def engine(**lists) -> Engine:
    cfg = Config()
    cfg.set("detectors.enabled.infra-names", True)       # off by default
    for k, v in lists.items():
        cfg.set("lists." + k, v)
    return Engine(engine_settings(cfg), Vault("t"))


class InfraTest(unittest.TestCase):
    def test_label_and_annotation_keys_stay(self):
        out = engine().process(K8S, "pseudonymize").output
        for key in ("argocd.argoproj.io/tracking-id:", "cert-manager.io/cluster-issuer:",
                    "app.kubernetes.io/instance:", "helm.sh/chart:", "-l app.kubernetes.io/name=shop"):
            self.assertIn(key, out)

    def test_customer_parts_replaced_consistently(self):
        e = engine()
        res = e.process(K8S, "pseudonymize")
        out = res.output
        self.assertNotIn("acme", out.lower())
        self.assertNotIn("mueller", out.lower())
        # generic words, product names and hashes stay
        for keep in ("bunkerweb-front", "scheduler-bunkerweb-front", "kunde-", "-web", "-prod",
                     "-front-instance", "-shop-7d9f8b6c5-xk2lp", "rollout restart deploy/", "bunkerweb-1.0.10"):
            self.assertIn(keep, out)
        # the same pseudonym everywhere (namespace, tracking id, -n, deploy/, domain)
        ns = out.split("namespace: ")[2].split("\n")[0]
        word = ns.split("-")[0]
        self.assertGreaterEqual(out.count(word), 6)
        self.assertIn(f"registry.{word}.de", out)
        self.assertEqual(e.revert(out).output, K8S)

    def test_allow_and_generic_lists(self):
        out = engine(allow_terms=["acme"]).process(K8S, "pseudonymize").output
        self.assertIn("acme-prod", out)
        out = engine(generic_labels_extra=["mueller"]).process(K8S, "pseudonymize").output
        self.assertIn("kunde-mueller-web", out)

    def test_plain_prose_and_code_untouched(self):
        text = "name: Install packages\nname: deploy_production\nreplicas: 3\nname: {{ .Release.Name }}\n"
        res = engine().process(text, "pseudonymize")
        self.assertEqual(res.output, text)


if __name__ == "__main__":
    unittest.main()
