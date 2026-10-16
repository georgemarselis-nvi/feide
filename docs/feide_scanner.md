# feide_scanner.py

The scanner checks the user entries of a directory against the rules
the Feide validator applies, so problems are found and fixed before the
Feide customer portal reports them. Against Active Directory it also
works as a general health check of the user data: leavers, inactive
accounts, missing phone numbers and names that disagree between fields.

It only reads. It never changes the directory.

## Requirements

- python3 and python3-ldap.
- A Kerberos ticket (kinit) for an account that may read the
  directory. The scanner binds with SASL GSSAPI only.
- Write access to /var/lib/feide for the state file, or --state
  pointing somewhere writable.
- Read access to /etc/feide/scanner-exceptions.tsv when exceptions are
  used, or --exceptions pointing at the file.

## Running it

Every account, from the repository root:

    /usr/bin/python3 scripts/feide_scanner.py --uri ldap://dc01.example.no

One account:

    /usr/bin/python3 scripts/feide_scanner.py --uri ldap://dc01.example.no --account ab1234

Only accounts that are people, leaving out one shared account:

    /usr/bin/python3 scripts/feide_scanner.py --uri ldap://dc01.example.no --account-pattern 'ab[0-9]{4}' --blocklist ab0001

--realm (example.no) and --base (DC=EXAMPLE,DC=NO) are derived from
the host in --uri; pass them to override. --help lists every option.

## Active Directory or OpenLDAP

The scanner reads the root DSE of the server. When supportedCapabilities
lists 1.2.840.113556.1.4.800 the server is Active Directory, otherwise
it is OpenLDAP. --server ad or --server openldap skips the detection.
The server type picks the defaults:

|                | Active Directory                              | OpenLDAP                                 |
|----------------|-----------------------------------------------|------------------------------------------|
| people         | (objectCategory=person)(objectClass=user)     | (objectClass=norEduPerson)               |
| disabled       | left out unless --include-disabled            | not applicable                           |
| uid            | sAMAccountName                                | uid                                      |
| ePPN           | userPrincipalName                             | eduPersonPrincipalName                   |
| AD checks      | yes                                           | no                                       |
| state file     | /var/lib/feide/scanner-last-ad.tsv            | /var/lib/feide/scanner-last-openldap.tsv |

--uid-attr, --eppn-attr, --filter and --state override the defaults.

## What it checks

On both server types:

- eduPersonPrincipalName in lower case only, with a realm part equal to
  the Feide realm.
- uid and mail in ASCII only.
- No leading, trailing or doubled whitespace and no control characters
  in cn, displayName, givenName, mail, sn and postalAddress.
- mobile in international format with no spaces: +47 followed by
  exactly eight digits for a Norwegian number, otherwise + and a country
  code with at least three digits in all. Sikt confirmed on 2026-10-15
  that the validator accepts foreign numbers in international format.
- One value only in displayName, givenName, sn and eduPersonPrincipalName.
- cn, sn, givenName, displayName, mail and eduPersonPrincipalName
  present.
- No uid or eduPersonPrincipalName shared by two accounts.
- eduPersonOrgUnitDN and eduPersonPrimaryOrgUnitDN resolve to entries,
  and the primary unit is among the units.

On Active Directory only:

- info (the Notes field) containing "skjulmeg" ("hide me"): the account
  must not reach Feide. It gets no other checks.
- description containing "Ekstern bruker": external users must not log
  in to Feide. The account gets no other checks.
- mobile and telephoneNumber present, and telephoneNumber and
  otherMobile in the same international format as mobile.
- displayName in the form "Surname, Given", with the same names as sn
  and givenName.
- lastLogonTimestamp: never logged on, or no logon in --stale-days
  (default 180). People who only use Microsoft 365 in the cloud show up
  here too, so check before disabling anyone.
- accountExpires: an enabled account whose expiry date has passed.

--account-pattern and --blocklist leave out accounts that are not
people (shared mailboxes, rooms, admin and service accounts) on either
server type. The pattern must match the whole uid, case ignored.

## Output

The findings are collected over the whole search and printed at the
end, sorted, one tab separated line each:

    <DN>	<attribute>	<message>	<value>

Then one line per message with the number of accounts it applies to:

    TOTAL	<count>	<message>

## Exceptions

Findings a person has accepted, for example while waiting on someone's
reply, go in /etc/feide/scanner-exceptions.tsv (or --exceptions), one
per line, tab separated:

    <uid>	<attribute or *>	<until YYYY-MM-DD>	<reason>

For example:

    ab1234	mobile	2026-11-30	foreign number, waiting on the user

A finding for that uid and attribute (* for every attribute of the
account) prints on an EXCEPTED line with the reason:

    EXCEPTED	<DN>	<attribute>	<message>	<value>	<reason>
    TOTAL	<count>	Excepted

Excepted findings stay out of the other totals, the NEW and GONE lines,
the state file and the exit code. From the day after the until date the
exception no longer applies and the finding comes back as NEW, so no
exception lasts for ever without someone renewing it. Lines starting
with # and empty lines are ignored; a missing file means no exceptions.
A malformed line stops the scanner with the file name and line number.

## Changes since the previous scan

Every full scan saves its findings to the state file and compares them
with the findings saved by the scan before it:

    NEW	<DN>	<attribute>	<message>	<value>
    GONE	<DN>	<attribute>	<message>	<value>
    TOTAL	<count>	New since the previous scan
    TOTAL	<count>	Gone since the previous scan

NEW is a finding the previous scan did not have; GONE is one that has
been fixed or whose account has gone. The first scan has nothing to
compare with and prints no NEW or GONE lines. Scans narrowed with
--account or --filter neither read nor save the state file, so a check
of one account never replaces the baseline.

## Exit codes

- 0: no findings, or only excepted ones.
- 1: findings.
- 2: an LDAP error, or the state file could not be saved.

## Limits

- The scanner binds with SASL GSSAPI only. The proxy in this repository
  lets only the Sikt system user search, so the scanner cannot read the
  proxy until it is given a way in.
- Searches are paged, since Active Directory stops an unpaged search at
  1000 entries. Paging through the proxy (back-sock) has not been tested.
- The required attribute list is not yet verified against the Feide
  information model.
