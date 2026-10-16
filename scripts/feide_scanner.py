#!/usr/bin/python3
# feide_scanner.py
# Checks the user entries of an LDAP directory for the attribute errors reported by the Feide customer portal and for violations of the eduPerson and norEdu schema definitions.
#
# run it as:
#
#   /usr/bin/python3 scripts/feide_scanner.py --uri ldap://dc01.dfo.no
#
# --realm (dfo.no) and --base (DC=DFO,DC=NO) are derived from the --uri host; pass them to override.
#
# one account only:
#
#   /usr/bin/python3 scripts/feide_scanner.py --uri ldap://dc01.dfo.no --account df1234
#
# Server type: the scanner reads the root DSE and treats the server as Active Directory when it lists
# the Active Directory capability (1.2.840.113556.1.4.800) in supportedCapabilities, and as OpenLDAP
# otherwise; --server ad or --server openldap skips the detection. The type picks the defaults:
#
#                     Active Directory                          OpenLDAP
#   people            (objectCategory=person)(objectClass=user) (objectClass=norEduPerson)
#   uid               sAMAccountName                            uid
#   ePPN              userPrincipalName                         eduPersonPrincipalName
#   AD checks         yes                                       no
#   state file        /var/lib/feide/scanner-last-ad.tsv        /var/lib/feide/scanner-last-openldap.tsv
#
# --uid-attr, --eppn-attr, --filter and --state override the defaults.
#
# Phone numbers (mobile, telephoneNumber and otherMobile) must be in international format with no spaces:
#   +47 followed by exactly eight digits for Norwegian numbers (+4792345678);
#   + and a country code for other countries, at least three digits in all (+43123456789).
# Sikt (Feide support, 2026-10-15): the Feide validator applies the Norwegian length check to +47 numbers
# and to numbers with no country code; for other country codes it only requires three digits.
# Assumption: norEduPersonLegalName is built from givenName plus sn, so its whitespace errors are reported under those two attributes.
# Assumption: the required attribute list (cn, sn, givenName, displayName, eduPersonPrincipalName, mail) is not yet verified against the Feide information model.
# The org unit checks only produce results against the proxy output, since AD holds no eduPerson attributes.
#
# Active Directory checks, which only run against Active Directory:
#   disabled accounts are left out unless --include-disabled, since they never reach Feide;
#   accounts whose info (Notes) field contains "skjulmeg" ("hide me") are reported, since they must
#   not reach Feide; the AD administrator keeps the marker, so the accounts are not touched;
#   accounts whose description contains "Ekstern bruker" are reported, since external users must
#   not log in to Feide; neither kind gets the other checks;
#   a missing mobile or telephoneNumber is reported, since both are filled when an account is created;
#   displayName must be "Surname, Given" with the same names as sn and givenName;
#   an account with no lastLogonTimestamp newer than --stale-days is reported; people who only use
#   Microsoft 365 in the cloud also show up here, so check before disabling anyone;
#   an enabled account whose accountExpires date has passed is reported.
#
# --account-pattern and --blocklist leave out accounts that are not people (for example ab[0-9]{4}
# or emp[0-9]{5}, and ab0001), on either server type.
#
# Output: the findings are collected over the whole search and printed at the end, sorted by DN,
# then one TOTAL line per message.
#
# Exceptions: findings a person has accepted are listed in --exceptions (default
# /etc/feide/scanner-exceptions.tsv), one per line, tab separated:
#
#   <uid>	<attribute or *>	<until YYYY-MM-DD>	<reason>
#
# A finding for that uid and attribute (* for every attribute) prints on an EXCEPTED line with the
# reason, and stays out of the totals, the NEW and GONE lines, the state file and the exit code.
# From the day after the until date the exception no longer applies and the finding returns as NEW.
# Lines starting with # and empty lines are ignored. A missing file means no exceptions.
#
# Changes since the previous scan:
#   every full scan saves its findings to the state file and compares them with the findings saved
#   by the scan before it; a finding that is new prints on a NEW line and a finding that has gone
#   prints on a GONE line, so support sees what changed;
#   the first scan has nothing to compare with, so it prints no NEW or GONE lines;
#   scans narrowed with --account or --filter neither read nor save the state file.
#
# Copyright (C) 2026 George Marselis <george.marselis@vetinst.no>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from __future__ import annotations

import argparse
import collections
import datetime
import os
import re
import sys
import urllib.parse
from typing import Iterator, Optional

import ldap
import ldap.dn
import ldap.filter
import ldap.sasl
from ldap.controls import SimplePagedResultsControl

# Decoded attributes of one entry: lower-case attribute name -> values.
Attrs = dict[str, list[str]]
# One problem found: (attribute, message, value).
Problem = tuple[str, str, str]
# One reported finding: (DN, uid, attribute, message, value).
Finding = tuple[str, str, str, str, str]
# Accepted findings: (lower-case uid, attribute or *) -> (until date, reason).
Exceptions = dict[tuple[str, str], tuple[datetime.date, str]]

FEIDE_CHECK_WHITESPACE_ATTRS: tuple[str, ...] = ("cn", "displayName", "givenName", "mail", "sn", "postalAddress")
FEIDE_CHECK_SINGLE_ATTRS: tuple[str, ...] = ("displayName", "givenName", "sn")
FEIDE_CHECK_REQUIRED_ATTRS: tuple[str, ...] = ("cn", "sn", "givenName", "displayName", "mail")
FEIDE_CHECK_ORGUNIT_ATTR: str = "eduPersonOrgUnitDN"
FEIDE_CHECK_PRIMARY_ORGUNIT_ATTR: str = "eduPersonPrimaryOrgUnitDN"
FEIDE_CHECK_WHITESPACE_RE: re.Pattern[str] = re.compile(r"^\s|\s$|\s{2,}")
FEIDE_CHECK_CONTROL_RE: re.Pattern[str] = re.compile(r"[\x00-\x1f\x7f]")
FEIDE_CHECK_NORWEGIAN_PHONE_PREFIX: str = "+47"
FEIDE_CHECK_NORWEGIAN_PHONE_RE: re.Pattern[str] = re.compile(r"^\+47[0-9]{8}$")
FEIDE_CHECK_INTERNATIONAL_PHONE_RE: re.Pattern[str] = re.compile(r"^\+[1-9][0-9]{2,}$")
FEIDE_CHECK_HIDE_MARKER: str = "skjulmeg"
FEIDE_CHECK_EXTERNAL_MARKER: str = "ekstern bruker"
# lastLogonTimestamp counts 100 ns intervals since 1601-01-01 UTC.
FEIDE_CHECK_FILETIME_EPOCH: datetime.datetime = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
# Listed in supportedCapabilities of the root DSE by Active Directory only.
FEIDE_CHECK_AD_CAPABILITY: str = "1.2.840.113556.1.4.800"
FEIDE_CHECK_SERVER_AD: str = "ad"
FEIDE_CHECK_SERVER_OPENLDAP: str = "openldap"
FEIDE_CHECK_STATE_DIR: str = "/var/lib/feide"
FEIDE_CHECK_EXCEPTIONS_FILE: str = "/etc/feide/scanner-exceptions.tsv"
# accountExpires holds this value, or 0, when the account never expires.
FEIDE_CHECK_FILETIME_NEVER: int = 0x7FFFFFFFFFFFFFFF
# Defaults per server type.
FEIDE_CHECK_PROFILES: dict[str, dict[str, str]] = {
    FEIDE_CHECK_SERVER_AD: {
        "people": "(objectCategory=person)(objectClass=user)",
        "uid_attr": "sAMAccountName",
        "eppn_attr": "userPrincipalName",
    },
    FEIDE_CHECK_SERVER_OPENLDAP: {
        "people": "(objectClass=norEduPerson)",
        "uid_attr": "uid",
        "eppn_attr": "eduPersonPrincipalName",
    },
}


def feide_check_parse_args(argv: list[str]) -> argparse.Namespace:
    """Takes the command line arguments; returns them parsed, with the realm
    and base derived from --uri when left out. The server type defaults are
    applied later by feide_check_apply_profile, once the server is known."""
    parser = argparse.ArgumentParser(description="Check LDAP user entries against the Feide customer portal attribute rules.")
    parser.add_argument("--uri", required=True, help="LDAP URI, for example ldap://dc01.dfo.no")
    parser.add_argument("--server", choices=("auto", FEIDE_CHECK_SERVER_AD, FEIDE_CHECK_SERVER_OPENLDAP), default="auto", help="server type; auto reads the root DSE (default auto)")
    parser.add_argument("--base", default=None, help="search base, for example DC=dfo,DC=no; derived from the realm when left out")
    parser.add_argument("--realm", default=None, help="Feide realm (schacHomeOrganization), for example dfo.no; derived from the --uri host when left out")
    parser.add_argument("--account", action="append", default=[], help="check only this uid; repeat for more, for example --account ab1234 --account emp56789")
    parser.add_argument("--include-disabled", action="store_true", help="Active Directory only: check disabled accounts too")
    parser.add_argument("--filter", default=None, help="raw LDAP search filter for special cases; overrides --account and --include-disabled")
    parser.add_argument("--state", default=None, help=f"file that keeps the findings of the previous full scan, to print NEW and GONE lines; default {FEIDE_CHECK_STATE_DIR}/scanner-last-<server type>.tsv")
    parser.add_argument("--exceptions", default=FEIDE_CHECK_EXCEPTIONS_FILE, help=f"file of accepted findings, one per line: uid, attribute or *, until date (YYYY-MM-DD) and reason, tab separated; default {FEIDE_CHECK_EXCEPTIONS_FILE}")
    parser.add_argument("--eppn-attr", default=None, help="attribute that becomes eduPersonPrincipalName; default userPrincipalName on Active Directory, eduPersonPrincipalName on OpenLDAP")
    parser.add_argument("--uid-attr", default=None, help="attribute that becomes uid; default sAMAccountName on Active Directory, uid on OpenLDAP")
    parser.add_argument("--account-pattern", default=None, help="check only accounts whose uid (see --uid-attr) matches this regular expression in full, ignoring case; any pattern works, for example ab[0-9]{4} or emp[0-9]{5}; without it every account is checked")
    parser.add_argument("--blocklist", default="", help="space separated uids to leave out even if they match the pattern, for example ab0001")
    parser.add_argument("--stale-days", type=int, default=180, help="Active Directory only: report accounts with no logon in this many days")
    parser.add_argument("--page-size", type=int, default=500, help="paged search page size")
    args = parser.parse_args(argv)
    args.account_re = re.compile(args.account_pattern, re.IGNORECASE) if args.account_pattern else None
    args.blocked = {name.lower() for name in args.blocklist.split()}
    args.now = datetime.datetime.now(datetime.timezone.utc)
    args.full_scan = not args.account and args.filter is None
    if args.realm is None:
        args.realm = feide_check_realm_from_uri(args.uri)
        if args.realm is None:
            parser.error(f"cannot derive the realm from --uri {args.uri}; pass --realm")
    if args.base is None:
        args.base = ",".join("DC=" + label.upper() for label in args.realm.split("."))
    try:
        args.excepted = feide_check_load_exceptions(args.exceptions)
    except ValueError as error:
        parser.error(str(error))
    return args


def feide_check_load_exceptions(path: str) -> Exceptions:
    """Takes the exceptions file path; returns the accepted findings it lists,
    or none when the file does not exist. Raises ValueError, naming the file
    and line, for a line without four tab separated fields or with a date
    that is not YYYY-MM-DD."""
    exceptions: Exceptions = {}
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        return exceptions
    for number, line in enumerate(lines, start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 4 or not all(field.strip() for field in fields):
            raise ValueError(f"{path} line {number}: expected uid, attribute or *, until date and reason, tab separated")
        uid, attr, until, reason = (field.strip() for field in fields)
        try:
            date = datetime.date.fromisoformat(until)
        except ValueError:
            raise ValueError(f"{path} line {number}: until date {until!r} is not YYYY-MM-DD") from None
        exceptions[(uid.lower(), attr.lower())] = (date, reason)
    return exceptions


def feide_check_exception(finding: Finding, args: argparse.Namespace) -> Optional[str]:
    """Takes a finding; returns the reason when an exception for its uid and
    attribute, or for its uid and *, is still in force today, otherwise
    None."""
    _, uid, attr, _, _ = finding
    today = args.now.date()
    for key in ((uid.lower(), attr.lower()), (uid.lower(), "*")):
        if key in args.excepted:
            until, reason = args.excepted[key]
            if today <= until:
                return reason
    return None


def feide_check_realm_from_uri(uri: str) -> Optional[str]:
    """Takes an LDAP URI; returns the domain of its host with the first label
    dropped (ldaps://dc01.dfo.no -> dfo.no), or None when the host is an
    address or has fewer than three labels."""
    host = urllib.parse.urlsplit(uri).hostname or ""
    labels = host.split(".")
    if len(labels) < 3 or all(label.isdigit() for label in labels) or ":" in host:
        return None
    return ".".join(labels[1:]).lower()


def feide_check_detect_server(conn: ldap.ldapobject.LDAPObject) -> str:
    """Takes a bound connection; returns "ad" when the root DSE lists the
    Active Directory capability in supportedCapabilities, otherwise
    "openldap"."""
    results = conn.search_s("", ldap.SCOPE_BASE, "(objectClass=*)", ["supportedCapabilities"])
    for _, entry in results:
        capabilities = [value.decode("utf-8", errors="replace") for value in (entry or {}).get("supportedCapabilities", [])]
        if FEIDE_CHECK_AD_CAPABILITY in capabilities:
            return FEIDE_CHECK_SERVER_AD
    return FEIDE_CHECK_SERVER_OPENLDAP


def feide_check_apply_profile(args: argparse.Namespace, server: str) -> None:
    """Takes the parsed arguments and the server type; fills in the uid and
    ePPN attributes, the search filter and the state file that were not
    given on the command line."""
    profile = FEIDE_CHECK_PROFILES[server]
    args.server = server
    args.is_ad = server == FEIDE_CHECK_SERVER_AD
    if args.uid_attr is None:
        args.uid_attr = profile["uid_attr"]
    if args.eppn_attr is None:
        args.eppn_attr = profile["eppn_attr"]
    if args.state is None:
        args.state = f"{FEIDE_CHECK_STATE_DIR}/scanner-last-{server}.tsv"
    if args.filter is None:
        args.filter = feide_check_build_filter(args, profile["people"])


def feide_check_build_filter(args: argparse.Namespace, people: str) -> str:
    """Takes the parsed arguments and the filter part that selects people;
    returns the search filter, without disabled accounts on Active Directory
    unless --include-disabled, narrowed to the --account uids when given."""
    parts = people
    if args.is_ad and not args.include_disabled:
        parts += "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    if args.account:
        uids = "".join(f"({args.uid_attr}={ldap.filter.escape_filter_chars(uid)})" for uid in args.account)
        parts += uids if len(args.account) == 1 else f"(|{uids})"
    return f"(&{parts})"


def feide_check_connect(uri: str) -> ldap.ldapobject.LDAPObject:
    """Takes an LDAP URI; returns a connection bound with SASL GSSAPI, using
    the Kerberos ticket of the user running the scanner."""
    conn = ldap.initialize(uri)
    conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    conn.set_option(ldap.OPT_REFERRALS, 0)
    conn.sasl_interactive_bind_s("", ldap.sasl.gssapi())
    return conn


def feide_check_search(conn: ldap.ldapobject.LDAPObject, base: str, search_filter: str, attrs: list[str], page_size: int) -> Iterator[tuple[str, dict[str, list[bytes]]]]:
    """Takes a connection, base, filter, attribute list and page size; yields
    (DN, raw entry) for every entry found, asking for one page at a time,
    since Active Directory stops an unpaged search at 1000 entries."""
    control = SimplePagedResultsControl(True, size=page_size, cookie=b"")
    while True:
        msgid = conn.search_ext(base, ldap.SCOPE_SUBTREE, search_filter, attrs, serverctrls=[control])
        _, results, _, server_controls = conn.result3(msgid)
        for dn, entry in results:
            if dn is not None:
                yield dn, entry
        cookie = b""
        for server_control in server_controls:
            if server_control.controlType == SimplePagedResultsControl.controlType:
                cookie = server_control.cookie
        if not cookie:
            return
        control.cookie = cookie


def feide_check_decode(entry: dict[str, list[bytes]]) -> Attrs:
    """Takes a raw entry; returns its attributes with lower-case names and
    values decoded from UTF-8."""
    return {name.lower(): [value.decode("utf-8", errors="replace") for value in values] for name, values in entry.items()}


def feide_check_entry(attrs: Attrs, args: argparse.Namespace) -> list[Problem]:
    """Takes the decoded attributes; returns the problems the Feide customer
    portal reports, on either server type."""
    errors: list[Problem] = []
    for value in attrs.get(args.eppn_attr.lower(), []):
        if value != value.lower():
            errors.append((args.eppn_attr, "Uppercase characters in eduPersonPrincipalName", value))
        _, separator, realm = value.rpartition("@")
        if not separator or realm.lower() != args.realm.lower():
            errors.append((args.eppn_attr, "Mismatch between schacHomeOrganization and realm in eduPersonPrincipalName", value))
    for value in attrs.get(args.uid_attr.lower(), []):
        if not value.isascii():
            errors.append((args.uid_attr, "Non-ASCII characters in uid", value))
    for name in FEIDE_CHECK_WHITESPACE_ATTRS:
        for value in attrs.get(name.lower(), []):
            if FEIDE_CHECK_WHITESPACE_RE.search(value):
                errors.append((name, "Extra whitespace in attribute: " + name, value))
            if FEIDE_CHECK_CONTROL_RE.search(value):
                errors.append((name, "Control characters in attribute: " + name, value))
    for value in attrs.get("mobile", []):
        message = feide_check_phone(value)
        if message:
            errors.append(("mobile", "mobile " + message, value))
    for value in attrs.get("mail", []):
        if not value.isascii():
            errors.append(("mail", "Non-ASCII characters in mail", value))
    for name in (args.eppn_attr,) + FEIDE_CHECK_SINGLE_ATTRS:
        values = attrs.get(name.lower(), [])
        if len(values) > 1:
            errors.append((name, "Multiple values in single-valued attribute: " + name, "; ".join(values)))
    for name in (args.eppn_attr,) + FEIDE_CHECK_REQUIRED_ATTRS:
        if not attrs.get(name.lower()):
            errors.append((name, "Missing required attribute: " + name, ""))
    return errors


def feide_check_phone(value: str) -> Optional[str]:
    """Takes a phone number; returns None when it is +47 and eight digits, or
    + and a country code with at least three digits in all; otherwise
    returns what is wrong with it."""
    if value.startswith(FEIDE_CHECK_NORWEGIAN_PHONE_PREFIX):
        if FEIDE_CHECK_NORWEGIAN_PHONE_RE.match(value):
            return None
        return "contains an invalid Norwegian phone number (+47 and eight digits)"
    if FEIDE_CHECK_INTERNATIONAL_PHONE_RE.match(value):
        return None
    return "is not in international format (+ and country code, no spaces)"


def feide_check_excluded_reason(attrs: Attrs) -> Optional[Problem]:
    """Takes the decoded attributes; returns why the account must not reach
    Feide ("skjulmeg" in info, or "Ekstern bruker" in description), or
    None."""
    for value in attrs.get("info", []):
        if FEIDE_CHECK_HIDE_MARKER in value.lower():
            return ("info", "Marked \"skjulmeg\" (hide me), must not reach Feide", value)
    for value in attrs.get("description", []):
        if FEIDE_CHECK_EXTERNAL_MARKER in value.lower():
            return ("description", "External user, must not log in to Feide", value)
    return None


def feide_check_is_person(attrs: Attrs, args: argparse.Namespace) -> bool:
    """Takes the decoded attributes; returns True when the account is a
    person by --account-pattern and --blocklist. Without a pattern every
    account is."""
    uid = (attrs.get(args.uid_attr.lower()) or [""])[0]
    if uid.lower() in args.blocked:
        return False
    return args.account_re is None or args.account_re.fullmatch(uid) is not None


def feide_check_filetime(value: str) -> Optional[datetime.datetime]:
    """Takes a lastLogonTimestamp or accountExpires value; returns a UTC
    datetime, or None for 0 and for the largest value, which both mean
    never."""
    ticks = int(value)
    if ticks <= 0 or ticks >= FEIDE_CHECK_FILETIME_NEVER:
        return None
    return FEIDE_CHECK_FILETIME_EPOCH + datetime.timedelta(microseconds=ticks // 10)


def feide_check_ad(attrs: Attrs, args: argparse.Namespace) -> list[Problem]:
    """Takes the decoded attributes of an Active Directory account; returns
    the problems that only make sense against Active Directory: phone
    fields, the "Surname, Given" displayName, the last logon and an
    expiry date that has passed."""
    errors: list[Problem] = []
    if not attrs.get("mobile"):
        errors.append(("mobile", "Missing mobile", ""))
    if not attrs.get("telephonenumber"):
        errors.append(("telephoneNumber", "Missing telephoneNumber", ""))
    for name in ("telephoneNumber", "otherMobile"):
        for value in attrs.get(name.lower(), []):
            message = feide_check_phone(value)
            if message:
                errors.append((name, name + " " + message, value))
    sn = (attrs.get("sn") or [""])[0]
    given = (attrs.get("givenname") or [""])[0]
    for value in attrs.get("displayname", []):
        surname, comma, rest = value.partition(",")
        if not comma:
            errors.append(("displayName", "displayName is not in the form \"Surname, Given\"", value))
            continue
        if not rest.startswith(" "):
            errors.append(("displayName", "No space after the comma in displayName", value))
        if surname.strip() != sn.strip() or rest.strip() != given.strip():
            errors.append(("displayName", "displayName differs from sn and givenName", f"{value} (sn={sn!r}, givenName={given!r})"))
    stamps = attrs.get("lastlogontimestamp", [])
    last = feide_check_filetime(stamps[0]) if stamps else None
    if last is None:
        errors.append(("lastLogonTimestamp", "Never logged on to on-premises Active Directory", ""))
    elif (args.now - last).days > args.stale_days:
        errors.append(("lastLogonTimestamp", f"No logon to on-premises Active Directory in {args.stale_days} days", last.date().isoformat()))
    expires = attrs.get("accountexpires", [])
    expiry = feide_check_filetime(expires[0]) if expires else None
    if expiry is not None and expiry <= args.now:
        errors.append(("accountExpires", "Account expired but still enabled", expiry.date().isoformat()))
    return errors


def feide_check_normalize_dn(dn: str) -> str:
    """Takes a DN; returns it in a canonical lower-case form for comparison."""
    try:
        return ldap.dn.dn2str(ldap.dn.str2dn(dn)).lower()
    except ldap.DECODING_ERROR:
        return dn.lower()


def feide_check_dn_exists(conn: ldap.ldapobject.LDAPObject, dn: str, cache: dict[str, bool]) -> bool:
    """Takes a connection, a DN and a cache; returns True when the DN resolves
    to an entry, asking the server once per DN."""
    key = feide_check_normalize_dn(dn)
    if key not in cache:
        try:
            conn.search_s(dn, ldap.SCOPE_BASE, "(objectClass=*)", ["1.1"])
            cache[key] = True
        except (ldap.NO_SUCH_OBJECT, ldap.INVALID_DN_SYNTAX):
            cache[key] = False
    return cache[key]


def feide_check_orgunits(conn: ldap.ldapobject.LDAPObject, attrs: Attrs, cache: dict[str, bool]) -> list[Problem]:
    """Takes a connection, the decoded attributes and the DN cache; returns
    the problems with eduPersonOrgUnitDN and eduPersonPrimaryOrgUnitDN."""
    errors: list[Problem] = []
    units = attrs.get(FEIDE_CHECK_ORGUNIT_ATTR.lower(), [])
    primaries = attrs.get(FEIDE_CHECK_PRIMARY_ORGUNIT_ATTR.lower(), [])
    unit_keys = {feide_check_normalize_dn(unit) for unit in units}
    for primary in primaries:
        if feide_check_normalize_dn(primary) not in unit_keys:
            errors.append((FEIDE_CHECK_PRIMARY_ORGUNIT_ATTR, "eduPersonPrimaryOrgUnitDN is not among eduPersonOrgUnitDN", primary))
    for name, values in ((FEIDE_CHECK_ORGUNIT_ATTR, units), (FEIDE_CHECK_PRIMARY_ORGUNIT_ATTR, primaries)):
        for value in values:
            if not feide_check_dn_exists(conn, value, cache):
                errors.append((name, "DN does not resolve to an entry in attribute: " + name, value))
    return errors


def feide_check_format(finding: Finding) -> str:
    """Takes a finding; returns it as one tab separated output line: DN,
    attribute, message and value."""
    dn, _, attr, message, value = finding
    return f"{dn}\t{attr}\t{message}\t{value!r}"


def feide_check_load_state(path: str) -> Optional[set[str]]:
    """Takes the state file path; returns the finding lines it holds, or None
    when there is no previous scan."""
    try:
        with open(path, encoding="utf-8") as handle:
            return {line.rstrip("\n") for line in handle if line.strip()}
    except FileNotFoundError:
        return None


def feide_check_save_state(path: str, lines: set[str]) -> None:
    """Takes the state file path and the finding lines; writes them through a
    temporary file, so a failed run never leaves half a state file behind."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        for line in sorted(lines):
            handle.write(line + "\n")
    os.replace(temporary, path)


def feide_check_scan(conn: ldap.ldapobject.LDAPObject, args: argparse.Namespace) -> set[Finding]:
    """Takes a bound connection and the parsed arguments; searches every page
    and returns all findings, including duplicate uid and ePPN values across
    accounts. Nothing is printed here."""
    attrs = [args.eppn_attr, args.uid_attr, "mobile", FEIDE_CHECK_ORGUNIT_ATTR, FEIDE_CHECK_PRIMARY_ORGUNIT_ATTR]
    if args.is_ad:
        attrs += ["telephoneNumber", "otherMobile", "info", "description", "lastLogonTimestamp", "accountExpires"]
    attrs += [name for name in FEIDE_CHECK_WHITESPACE_ATTRS + FEIDE_CHECK_REQUIRED_ATTRS if name not in attrs]
    findings: set[Finding] = set()
    seen: dict[str, collections.defaultdict[str, set[str]]] = {args.eppn_attr: collections.defaultdict(set), args.uid_attr: collections.defaultdict(set)}
    cache: dict[str, bool] = {}
    uids: dict[str, str] = {}
    for dn, entry in feide_check_search(conn, args.base, args.filter, attrs, args.page_size):
        decoded = feide_check_decode(entry)
        if not feide_check_is_person(decoded, args):
            continue
        uid = (decoded.get(args.uid_attr.lower()) or [""])[0]
        uids[dn] = uid
        excluded = feide_check_excluded_reason(decoded) if args.is_ad else None
        if excluded:
            findings.add((dn, uid) + excluded)
            continue
        problems = feide_check_entry(decoded, args) + feide_check_orgunits(conn, decoded, cache)
        if args.is_ad:
            problems += feide_check_ad(decoded, args)
        for problem in problems:
            findings.add((dn, uid) + problem)
        for name, index in seen.items():
            for value in decoded.get(name.lower(), []):
                index[value.lower()].add(dn)
    for name, index in seen.items():
        for value, dns in index.items():
            if len(dns) > 1:
                for dn in dns:
                    findings.add((dn, uids[dn], name, "Duplicate value in attribute: " + name, value))
    return findings


def feide_check_report(findings: set[Finding], args: argparse.Namespace) -> int:
    """Takes all findings and the parsed arguments; prints the findings
    covered by an exception on EXCEPTED lines, the rest sorted, one TOTAL
    line per message and, on a full scan, the NEW and GONE lines against
    the state file, which it then replaces. Excepted findings stay out of
    the totals, the state file and the exit code. Returns the exit code:
    0 for no findings, 1 for findings, 2 when the state file cannot be
    saved."""
    excepted: list[tuple[Finding, str]] = []
    open_findings: set[Finding] = set()
    for finding in findings:
        reason = feide_check_exception(finding, args)
        if reason is None:
            open_findings.add(finding)
        else:
            excepted.append((finding, reason))
    findings = open_findings
    for finding in sorted(findings):
        print(feide_check_format(finding))
    for finding, reason in sorted(excepted):
        print(f"EXCEPTED\t{feide_check_format(finding)}\t{reason}")
    users: collections.defaultdict[str, set[str]] = collections.defaultdict(set)
    for dn, _, _, message, _ in findings:
        users[message].add(dn)
    for message in sorted(users):
        print(f"TOTAL\t{len(users[message])}\t{message}")
    if excepted:
        print(f"TOTAL\t{len(excepted)}\tExcepted")
    if args.full_scan:
        lines = {feide_check_format(finding) for finding in findings}
        previous = feide_check_load_state(args.state)
        if previous is not None:
            new = sorted(lines - previous)
            gone = sorted(previous - lines)
            for line in new:
                print(f"NEW\t{line}")
            for line in gone:
                print(f"GONE\t{line}")
            print(f"TOTAL\t{len(new)}\tNew since the previous scan")
            print(f"TOTAL\t{len(gone)}\tGone since the previous scan")
        try:
            feide_check_save_state(args.state, lines)
        except OSError as error:
            print(f"feide_check: cannot save {args.state}: {error}", file=sys.stderr)
            return 2
    return 1 if findings else 0


def feide_check_main(argv: list[str]) -> int:
    """Takes the command line arguments; connects, works out the server type,
    scans and reports. Returns the exit code."""
    args = feide_check_parse_args(argv)
    try:
        conn = feide_check_connect(args.uri)
        server = feide_check_detect_server(conn) if args.server == "auto" else args.server
        feide_check_apply_profile(args, server)
        findings = feide_check_scan(conn, args)
        conn.unbind_s()
    except ldap.LDAPError as error:
        print(f"feide_check: {error}", file=sys.stderr)
        return 2
    return feide_check_report(findings, args)


if __name__ == "__main__":
    sys.exit(feide_check_main(sys.argv[1:]))
