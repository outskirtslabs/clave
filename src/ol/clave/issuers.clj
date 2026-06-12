(ns ol.clave.issuers
  "Convenience ACME directory URLs for well-known certificate authorities.

  Check each provider's documentation before use. Some providers require
  External Account Binding (EAB), account setup, or payment.

  Compatibility note: these URLs point to external services and may change or
  disappear without a major version bump.")

(def lets-encrypt-staging-ca
  "Let's Encrypt staging ACME directory URL.

  See https://letsencrypt.org/docs/staging-environment/."
  "https://acme-staging-v02.api.letsencrypt.org/directory")

(def lets-encrypt-production-ca
  "Let's Encrypt production ACME directory URL.

  See https://letsencrypt.org/getting-started/."
  "https://acme-v02.api.letsencrypt.org/directory")

(def zerossl-production-ca
  "ZeroSSL production ACME directory URL.

  See https://zerossl.com/documentation/acme/."
  "https://acme.zerossl.com/v2/DV90")

(def google-trust-staging-ca
  "Google Trust Services staging ACME directory URL.

  See https://cloud.google.com/certificate-manager/docs/public-ca-tutorial."
  "https://dv.acme-v02.test-api.pki.goog/directory")

(def google-trust-production-ca
  "Google Trust Services production ACME directory URL.

  See https://cloud.google.com/certificate-manager/docs/public-ca-tutorial."
  "https://dv.acme-v02.api.pki.goog/directory")
