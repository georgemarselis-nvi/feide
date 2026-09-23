# feide
FEIDE host-organisation catalog for the Norwegian Veterinary Institute

## Requirements

This list has two halves:
- Sikt constraints
- Active Directory constraints

### Sikt constraints

- The NVI catalog must be reachable over LDAPS. The certificate must be issued from
  a public CA. 
- TLS 1.2 must stay enabled. TLS 1.3 alongside it is fine. Sikt will try to use TLS
  1.3, but some apps require TLS 1.2, so it is used as a common denominator. A TLS
  1.3-only server is unsupported by Sikt and fails testing on ssltest.feide.no.
- Cipher suites: FEIDE lists twelve acceptable suites and requires support for at
  least one of them. We will use the the four strongest and ease towards the full
  list if Sikt fails to connect.

  Starting set:

  - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
  - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   (0xc030)
  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   (0xc02f)

  The remaining eight, in :

  - TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    (0xc00a)
  - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      (0xc014)
  - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    (0xc009)
  - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      (0xc013)
  - TLS_RSA_WITH_AES_256_GCM_SHA384         (0x009d)
  - TLS_RSA_WITH_AES_128_GCM_SHA256         (0x009c)
  - TLS_RSA_WITH_AES_256_CBC_SHA            (0x0035)
  - TLS_RSA_WITH_AES_128_CBC_SHA            (0x002f)

- TLSProtocolMin 3.3 (TLS 1.2), per the requirement above.
- The norEdu schema is loaded as delivered by Sikt (schema/52-noredu.ldif)
- The directory carries one organisation entry (norEduOrg) with the organisation
  number, the legal name, the acronym and the schema version.
- The organisation number must match Brønnøysundregisteret exactly. A mismatch
  breaks service activation for individual units. NVI is 970955623.
- Sikt has an LDAP crawler which searches the whole person subtree, either to find
  faults in LDAP or to validate a user. LDAP ACLs must permit that.
- The catalog exposes only the minimal attribute set: the mandatory attributes
  plus displayName, mail, mobile, eduPersonAffiliation and eduPersonScopedAffiliation.
  We operate on an allowlist, not a denylist. Anything beyond it is added when a
  specitic service requires it.
  
- Attribute hygiene enforced by the FEIDE validator:
  - eduPersonPrincipalName contains no uppercase characters.
  - uid contains no non-ASCII characters.
  - schacHomeOrganization equals the realm part of eduPersonPrincipalName.
  - No leading, trailing or doubled whitespace in cn, displayName, givenName,
    mail, norEduPersonLegalName, sn or postalAddress.
  - mobile holds a valid Norwegian number.
- Two-factor authentication is in place before the catalog is considered done.
- Client networks reach idp.feide.no, auth.dataporten.no, api.dataporten.no and
  groups-api.dataporten.no from the browser.

### Active Directory constraints

The catalog holds no user data of its own. Every user attribute is read live from
Active Directory, so the rules below are Active Directory rules, not catalog rules.

- Usernames are never reused. A VI number belongs to one person forever, since
  FEIDE identities are long-lived and a reissued username silently grants a new
  person the old person's access. The four-digit VI pool holds 10000 numbers and
  about 3000 are consumed, which has to be widened before it runs out.
- Disabled means gone. Accounts with the disable bit set in userAccountControl are
  filtered out of the catalog, so a leaver stops being able to log in.
- One mail attribute. The on-prem mail attribute is authoritative. NVI runs hybrid
  Exchange with a one-way sync, so aliases added cloud-side never write back and
  are invisible to anything reading Active Directory, this catalog included.
- Phone fields hold phones. mobile is E.164 and holds nothing else.
- Name attributes are clean: no doubled spaces, no stray leading or trailing
  whitespace, no non-ASCII in the account name. Every validator error above
  originates in Active Directory and is fixed there, not worked around in the
  proxy.
- Active Directory carries no eduPerson or inetOrgPerson classes. In NVI's
  directory cn holds the username and displayName is surname-first, so the
  mapping rewrites them rather than passing them through.
- Attributes Active Directory cannot supply (norEduPersonNIN, the constant-value
  affiliation attributes) do not come from the proxy and are resolved separately.


### Implementation

 The public certificates for NVI come from TrustZone over ACME, issued by GlobalSign. 
