(ns ol.clave.protocols)

(defprotocol AsymmetricKeyPair
  "Protocol for asymmetric key pairs used in ACME operations."
  (keypair [this] "Return a java.security.KeyPair")
  (private [this]
    "Return the java.security.PrivateKey half of the key pair.")
  (public [this]
    "Return the java.security.PublicKey half of the key pair.")
  (algo [this] "Return the key type as a keyword :ol.clave.algo/rsa")
  (describe [this] "Returns a map describing various key attributes")
  (serialize [this] "Returns a map with two keys containing the pem-encoded private and public"))
