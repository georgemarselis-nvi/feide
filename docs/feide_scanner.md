# feide_scanner.py

The scanner checks the user entries of a directory against the rules
the FEIDE validator applies, so problems are found and fixed before the
FEIDE customer portal reports them. Against Active Directory it also
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

    scripts/feide_scanner.py --uri ldap://dc01.example.no

One account:

    scripts/feide_scanner.py --uri ldap://dc01.example.no --account ab1234

Only accounts that are people, leaving out one shared account:

    scripts/feide_scanner.py --uri ldap://dc01.example.no --account-pattern 'ab[0-9]{4}' --blocklist ab0001

Only the findings for some attributes, comma separated:

    scripts/feide_scanner.py --uri ldap://dc01.example.no --only mail,mobile

--only takes the attribute names in the third column of the output;
an unknown name stops the scanner with the list of valid ones. Tab
completion for them, installed once:

    cp scripts/feide_scanner.bash-completion /etc/bash_completion.d/feide_scanner

Every account except some, comma separated full account names:

    scripts/feide_scanner.py --uri ldap://dc01.example.no --exclude ab1234,ab5678

--exclude matches the CN of the DN, case ignored. A name that does not
match --account-pattern, or that is not among the scanned accounts,
stops the scanner with an error, so a typo never silently shows the
account again. Like --only, it changes only what is printed; the state
file still records every finding.

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

The rules and where each comes from are in feide_scanner_rules.md.
--account-pattern and --blocklist leave out accounts that are not
people (shared mailboxes, rooms, admin and service accounts) on either
server type. The pattern must match the whole uid, case ignored.

## Output

One line per finding, then one TOTAL line per message with the number
of accounts it applies to:

    <status>	<DN>	<attribute>	<message>	<value>
    TOTAL	<count>	<message>

The status is empty for an open finding, EXCEPTED (followed by the
reason after the value), INFO (information, not a failure: it does not
count in the exit code and is not written to the state file) or NEW. Every column is padded with spaces to
its widest value and followed by a tab, so the columns line up on screen
and the output still splits on tabs; the finding lines and the TOTAL
lines are each aligned on their own. Strip the padding when reading a
field.

## Exceptions

Findings a person has accepted, for example while waiting on someone's
reply, go in /etc/feide/scanner-exceptions.tsv (or --exceptions), one
per line, tab separated:

    <uid>	<attribute or *>	<until YYYY-MM-DD>	<reason>

For example:

    ab1234	mobile	2026-11-30	foreign number, waiting on the user

A finding for that uid and attribute (* for every attribute of the
account) prints on an EXCEPTED line with the reason and stays out of
the totals, the state file and the exit code. From the day after the
until date the finding comes back, so no exception lasts for ever
without someone renewing it. Lines starting with # and empty lines are
ignored; a missing file means no exceptions. A malformed line stops the
scanner with the file name and line number.

## Changes since the previous scan

Every full scan saves its findings to the state file and compares them
with the scan before it. A finding the previous scan did not have is
printed again on a NEW line; the totals end with the number of new and
fixed findings. The first scan has nothing to compare with. Scans
narrowed with --account or --filter neither read nor save the state
file, so a check of one account never replaces the baseline.

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
- The required attribute list is not yet verified against the FEIDE
  information model.
