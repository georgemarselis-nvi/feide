# Scanner rules

The rules scripts/feide_scanner.py checks, and where each one comes from.
How to run the scanner is in feide_scanner.md.

## Feide validator rules

From NVI's error list in the Feide customer portal, retrieved
20.09.2026 22:01, with Sikt's answer on phone numbers of 15.10.2026.
Checked on Active Directory and OpenLDAP.

1. eduPersonPrincipalName: lower case only.
2. uid: ASCII only.
3. schacHomeOrganization must equal the realm part of
   eduPersonPrincipalName.
4. No leading, trailing or doubled whitespace in cn, displayName,
   givenName, mail, norEduPersonLegalName, sn or postalAddress.
5. mobile must be a valid phone number in international format. A
   number with +47, or with no country code, must be a valid Norwegian
   number: +47 and eight digits (+4792345678). A number with another
   country code only needs at least three digits (+43123456789).

## Schema rules

From the eduPerson and norEdu schema definitions. Checked on Active
Directory and OpenLDAP.

6. displayName, givenName, sn and eduPersonPrincipalName hold one value
   each.
7. No control characters in cn, displayName, givenName, mail, sn or
   postalAddress.
8. mail: ASCII only.
9. cn, sn, givenName, displayName, mail and eduPersonPrincipalName must
   be present. This list is not yet verified against the Feide
   information model.
10. No two accounts share a uid or an eduPersonPrincipalName, since
    Feide would see them as one person.
11. eduPersonOrgUnitDN and eduPersonPrimaryOrgUnitDN must resolve to
    entries, and the primary unit must be among the units. These only
    produce results against the proxy, since Active Directory holds no
    eduPerson attributes.

## Active Directory rules

NVI's own rules for the data in Active Directory. Checked on Active
Directory only.

12. Disabled accounts are not checked unless --include-disabled, since
    they never reach Feide.
13. An account whose info (Notes) field contains "skjulmeg" ("hide me")
    must not reach Feide. The Active Directory administrator keeps the
    marker on purpose, so the account is reported and not changed. It
    gets no other checks.
14. An account whose description contains "Ekstern bruker" belongs to
    an external user, who must not log in to Feide. It is reported and
    gets no other checks.
15. mobile and telephoneNumber are both filled in when an account is
    created; a missing one is reported.
16. telephoneNumber and otherMobile follow the same format as mobile
    (rule 5). Secondary numbers go in otherMobile, without spaces.
17. displayName is "Surname, Given", with the same names as sn and
    givenName.
18. An account never logged on, or with no logon in --stale-days
    (default 180), is reported. People who only use Microsoft 365 in
    the cloud show up here too, so check before disabling anyone.

## Which accounts are people

On either server type, --account-pattern (a regular expression the
whole uid must match, case ignored) and --blocklist leave out shared
mailboxes, rooms, admin and service accounts.
