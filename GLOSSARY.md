# ACME Certificate Automation

Clave implements the ACME client role defined by RFC 8555 and the ACME Renewal Information (ARI) extension defined by RFC 9773. It obtains and maintains X.509 certificates that attest to identifier/key bindings, supporting both direct certificate-management actions and ongoing lifecycle automation.

## Certificate and Identifier Language

**Identifier**:
A typed value that an ACME account seeks authorization to represent and include in a certificate. RFC 8555 defines the `dns` identifier type; Clave also supports `ip` identifiers.
_Avoid_: Domain when IP addresses are also in scope

**Domain**:
A DNS identifier and the primary ACME use case. RFC 8555 uses a general identifier model while centering domain validation; Clave likewise favors domain-oriented language because developers overwhelmingly manage and search for domains.

**Managed Identifier**:
A DNS or IP identifier for which Clave assumes ongoing responsibility for obtaining and renewing a certificate. Clave uses the developer-facing phrase *managed domain* for discoverability because domains dominate normal usage.

**Certificate**:
An X.509 credential that attests to a binding between identifiers and a public key for a limited validity period. The corresponding private key is separate from the certificate.

**Certificate Chain**:
One or more certificates ordered with the end-entity certificate first and each following certificate normally certifying the preceding one. A trust anchor may be omitted because trust anchors are distributed independently.

**Certificate Bundle**:
Clave's complete TLS material for serving a certificate: the certificate chain, corresponding private key, identifiers, validity period, issuer information, and optional stapled OCSP response.
_Avoid_: Certificate when the private key or associated maintenance data is also meant

**Certificate Issuance**:
The ACME server process that creates a requested certificate after the client satisfies the order requirements and finalizes the order.

**Obtain**:
The client-side process of requesting and downloading a newly issued certificate. Clave obtains a certificate; the ACME server issues it.
_Avoid_: Issue when describing Clave's side of the exchange

**Renewal**:
Acquiring a new certificate intended to replace an existing certificate through a new order. In ARI terminology, renewal also encompasses re-key and modification; it never mutates the existing certificate resource.

**Revocation**:
A certificate-management action that invalidates a certificate before its scheduled expiration.

## ACME Roles and Resources

**ACME Client**:
The protocol participant that requests certificate-management actions such as issuance or revocation. Clave acts as an ACME client.

**ACME Server**:
The protocol participant, operated by a Certificate Authority, that handles client requests and performs authorized certificate-management actions.

**Certificate Authority (CA)**:
The authority that verifies certificate applicants and issues certificates. A CA operates the ACME server but remains distinct from the server's protocol role.

**Issuer**:
Clave's term for a certificate source it can try when obtaining a certificate. In protocol language, Clave contacts an ACME server operated by a CA; use those terms when that distinction matters.

**Directory**:
The ACME server resource that lists the URLs for its certificate-management operations and optional service metadata. It is the only server URL an ACME client needs configured initially.

**ACME Account**:
A server-side account represented by account metadata and authenticated with a dedicated account key pair. Orders and authorizations are associated with the account.
_Avoid_: User account

**Account Key Pair**:
The dedicated key pair with which an ACME client authenticates requests for one account. It is distinct from every certificate key pair and must not be included in a certificate.

**Order**:
An ACME client's request for a certificate and the resource that tracks that request through issuance. It names the requested identifiers and the authorizations the server requires.

**Authorization**:
An ACME server's authorization for an account to represent one identifier. A pending authorization offers challenges; a valid authorization records successful validation.

**Challenge**:
An ACME server's offer to validate a client's control of an identifier using a specific validation method.

**Challenge Solver**:
Clave's client-side behavior for provisioning, waiting for, and de-provisioning the resources needed to fulfill a selected challenge. RFC 8555 describes these actions but does not use *solver* as a protocol term.
_Avoid_: Validator—the ACME server validates; the client fulfills the challenge

## Certificate Maintenance

**ACME Renewal Information (ARI)**:
The RFC 9773 extension through which an ACME server suggests when a client should attempt renewal and a client can identify the certificate an order replaces.

**Suggested Renewal Window**:
The interval in a RenewalInfo object during which the CA recommends renewing a certificate. A client chooses its own renewal time within that window.

**Stapled OCSP Response**:
A signed certificate-status response kept with a certificate so a TLS server can provide current revocation information during a handshake. Clave commonly calls this an *OCSP staple*.
