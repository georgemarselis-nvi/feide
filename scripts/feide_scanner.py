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
# Phone numbers (mobile, telephoneNumber and otherMobile) must be in international format with no spaces:
#   +47 followed by exactly eight digits for Norwegian numbers (+4792345678);
#   + and a country code for other countries, at least three digits in all (+43123456789).
# Sikt (Feide support, 2026-10-15): the Feide validator applies the Norwegian length check to +47 numbers
# and to numbers with no country code; for other country codes it only requires three digits.
# Assumption: norEduPersonLegalName is built from givenName plus sn, so its whitespace errors are reported under those two attributes.
# Assumption: the required attribute list (cn, sn, givenName, displayName, eduPersonPrincipalName, mail) is not yet verified against the Feide information model.
# The org unit checks only produce results against the proxy output, since AD holds no eduPerson attributes.
#
# Active Directory checks, which only produce results against AD itself:
#   disabled accounts are left out unless --include-disabled, since they never reach Feide;
#   --account-pattern and --blocklist leave out accounts that are not people (NVI: vi[0-9]{4}, vi1576);
#   accounts whose info (Notes) field contains "skjulmeg" ("hide me") are skipped, since they must
#   not reach Feide; the AD administrator keeps the marker, so the accounts are not touched;
#   accounts whose description contains "Ekstern bruker" (for example "Ekstern brukere (Renholdere)")
#   are skipped, since external users must not log in to Feide;
#   each skipped account is printed on a SKIPPED line with the reason, and skips do not count as errors;
#   a missing mobile or telephoneNumber is reported, since both are filled when an account is created;
#   displayName must be "Surname, Given" with the same names as sn and givenName;
#   an account with no lastLogonTimestamp newer than --stale-days is reported; people who only use
#   Microsoft 365 in the cloud also show up here, so check before disabling anyone.
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

import argparse
import collections
import datetime
import re
import sys
import urllib.parse

import ldap
import ldap.dn
import ldap.filter
import ldap.sasl
from ldap.controls import SimplePagedResultsControl

FEIDE_CHECK_WHITESPACE_ATTRS = ("cn", "displayName", "givenName", "mail", "sn", "postalAddress")
FEIDE_CHECK_SINGLE_ATTRS = ("displayName", "givenName", "sn")
FEIDE_CHECK_REQUIRED_ATTRS = ("cn", "sn", "givenName", "displayName", "mail")
FEIDE_CHECK_ORGUNIT_ATTR = "eduPersonOrgUnitDN"
FEIDE_CHECK_PRIMARY_ORGUNIT_ATTR = "eduPersonPrimaryOrgUnitDN"
FEIDE_CHECK_WHITESPACE_RE = re.compile(r"^\s|\s$|\s{2,}")
FEIDE_CHECK_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
FEIDE_CHECK_NORWEGIAN_PHONE_PREFIX = "+47"
FEIDE_CHECK_NORWEGIAN_PHONE_RE = re.compile(r"^\+47[0-9]{8}$")
FEIDE_CHECK_INTERNATIONAL_PHONE_RE = re.compile(r"^\+[1-9][0-9]{2,}$")
FEIDE_CHECK_HIDE_MARKER = "skjulmeg"
FEIDE_CHECK_EXTERNAL_MARKER = "ekstern bruker"
# lastLogonTimestamp counts 100 ns intervals since 1601-01-01 UTC.
FEIDE_CHECK_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def feide_check_parse_args(argv):
    parser = argparse.ArgumentParser(description="Check LDAP user entries against the Feide customer portal attribute rules.")
    parser.add_argument("--uri", required=True, help="LDAP URI, for example ldap://dc01.dfo.no")
    parser.add_argument("--base", default=None, help="search base, for example DC=dfo,DC=no; derived from the realm when left out")
    parser.add_argument("--realm", default=None, help="Feide realm (schacHomeOrganization), for example dfo.no; derived from the --uri host when left out")
    parser.add_argument("--account", action="append", default=[], help="check only this uid; repeat for more, for example --account vi1234 --account vi5678")
    parser.add_argument("--include-disabled", action="store_true", help="check disabled accounts too")
    parser.add_argument("--filter", default=None, help="raw LDAP search filter for special cases; overrides --account and --include-disabled")
    parser.add_argument("--eppn-attr", default="userPrincipalName", help="attribute that becomes eduPersonPrincipalName")
    parser.add_argument("--uid-attr", default="sAMAccountName", help="attribute that becomes uid")
    parser.add_argument("--account-pattern", default=None, help="regular expression a uid must match in full to be checked, for example vi[0-9]{4}")
    parser.add_argument("--blocklist", default="", help="space separated uids to leave out even if they match the pattern, for example vi1576")
    parser.add_argument("--stale-days", type=int, default=180, help="report accounts with no logon in this many days")
    parser.add_argument("--page-size", type=int, default=500, help="paged search page size")
    args = parser.parse_args(argv)
    args.account_re = re.compile(args.account_pattern, re.IGNORECASE) if args.account_pattern else None
    args.blocked = {name.lower() for name in args.blocklist.split()}
    args.now = datetime.datetime.now(datetime.timezone.utc)
    if args.realm is None:
        args.realm = feide_check_realm_from_uri(args.uri)
        if args.realm is None:
            parser.error(f"cannot derive the realm from --uri {args.uri}; pass --realm")
    if args.base is None:
        args.base = ",".join("DC=" + label.upper() for label in args.realm.split("."))
    if args.filter is None:
        args.filter = feide_check_build_filter(args)
    return args


# Takes an LDAP URI; returns the domain of its host with the first label
# dropped (ldaps://dc02.vetinst.no -> vetinst.no), or None when the host
# is an address or has fewer than three labels.
def feide_check_realm_from_uri(uri):
    host = urllib.parse.urlsplit(uri).hostname or ""
    labels = host.split(".")
    if len(labels) < 3 or all(label.isdigit() for label in labels) or ":" in host:
        return None
    return ".".join(labels[1:]).lower()


# Takes the parsed arguments; returns the search filter for people,
# without disabled accounts unless --include-disabled, narrowed to the
# --account uids when given.
def feide_check_build_filter(args):
    parts = "(objectCategory=person)(objectClass=user)"
    if not args.include_disabled:
        parts += "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    if args.account:
        uids = "".join(f"({args.uid_attr}={ldap.filter.escape_filter_chars(uid)})" for uid in args.account)
        parts += uids if len(args.account) == 1 else f"(|{uids})"
    return f"(&{parts})"


def feide_check_connect(uri):
    conn = ldap.initialize(uri)
    conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    conn.set_option(ldap.OPT_REFERRALS, 0)
    conn.sasl_interactive_bind_s("", ldap.sasl.gssapi())
    return conn


def feide_check_search(conn, base, search_filter, attrs, page_size):
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


def feide_check_decode(entry):
    return {name.lower(): [value.decode("utf-8", errors="replace") for value in values] for name, values in entry.items()}


def feide_check_entry(attrs, args):
    errors = []
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


# Takes a phone number; returns None when it is +47 and eight digits, or +
# and a country code with at least three digits in all; otherwise returns
# what is wrong with it.
def feide_check_phone(value):
    if value.startswith(FEIDE_CHECK_NORWEGIAN_PHONE_PREFIX):
        if FEIDE_CHECK_NORWEGIAN_PHONE_RE.match(value):
            return None
        return "contains an invalid Norwegian phone number (+47 and eight digits)"
    if FEIDE_CHECK_INTERNATIONAL_PHONE_RE.match(value):
        return None
    return "is not in international format (+ and country code, no spaces)"


# Takes the decoded attributes; returns why the account must not reach
# Feide ("skjulmeg" in info, or "Ekstern bruker" in description), or None.
def feide_check_excluded_reason(attrs):
    for value in attrs.get("info", []):
        if FEIDE_CHECK_HIDE_MARKER in value.lower():
            return ("info", "Skipped: marked \"skjulmeg\" (hide me), must not reach Feide", value)
    for value in attrs.get("description", []):
        if FEIDE_CHECK_EXTERNAL_MARKER in value.lower():
            return ("description", "Skipped: external user, must not log in to Feide", value)
    return None


# Takes the decoded attributes; returns True when the account is a person
# by --account-pattern and --blocklist. Without a pattern every account is.
def feide_check_is_person(attrs, args):
    uid = (attrs.get(args.uid_attr.lower()) or [""])[0]
    if uid.lower() in args.blocked:
        return False
    return args.account_re is None or args.account_re.fullmatch(uid) is not None


# Takes a lastLogonTimestamp value; returns a UTC datetime, or None for 0.
def feide_check_filetime(value):
    ticks = int(value)
    if ticks <= 0:
        return None
    return FEIDE_CHECK_FILETIME_EPOCH + datetime.timedelta(microseconds=ticks // 10)


def feide_check_ad(attrs, args):
    errors = []
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
    return errors


def feide_check_normalize_dn(dn):
    try:
        return ldap.dn.dn2str(ldap.dn.str2dn(dn)).lower()
    except ldap.DECODING_ERROR:
        return dn.lower()


def feide_check_dn_exists(conn, dn, cache):
    key = feide_check_normalize_dn(dn)
    if key not in cache:
        try:
            conn.search_s(dn, ldap.SCOPE_BASE, "(objectClass=*)", ["1.1"])
            cache[key] = True
        except (ldap.NO_SUCH_OBJECT, ldap.INVALID_DN_SYNTAX):
            cache[key] = False
    return cache[key]


def feide_check_orgunits(conn, attrs, cache):
    errors = []
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


def feide_check_report(dn, attr, message, value, users):
    print(f"{dn}\t{attr}\t{message}\t{value!r}")
    users[message].add(dn)


def feide_check_main(argv):
    args = feide_check_parse_args(argv)
    attrs = [args.eppn_attr, args.uid_attr, "mobile", "telephoneNumber", "otherMobile", "info", "description", "lastLogonTimestamp", FEIDE_CHECK_ORGUNIT_ATTR, FEIDE_CHECK_PRIMARY_ORGUNIT_ATTR]
    attrs += [name for name in FEIDE_CHECK_WHITESPACE_ATTRS + FEIDE_CHECK_REQUIRED_ATTRS if name not in attrs]
    users = collections.defaultdict(set)
    skipped = collections.Counter()
    seen = {args.eppn_attr: collections.defaultdict(set), args.uid_attr: collections.defaultdict(set)}
    cache = {}
    try:
        conn = feide_check_connect(args.uri)
        for dn, entry in feide_check_search(conn, args.base, args.filter, attrs, args.page_size):
            decoded = feide_check_decode(entry)
            if not feide_check_is_person(decoded, args):
                continue
            excluded = feide_check_excluded_reason(decoded)
            if excluded:
                attr, message, value = excluded
                print(f"SKIPPED\t{dn}\t{attr}\t{message}\t{value!r}")
                skipped[message] += 1
                continue
            for attr, message, value in feide_check_entry(decoded, args) + feide_check_ad(decoded, args) + feide_check_orgunits(conn, decoded, cache):
                feide_check_report(dn, attr, message, value, users)
            for name, index in seen.items():
                for value in decoded.get(name.lower(), []):
                    index[value.lower()].add(dn)
        conn.unbind_s()
    except ldap.LDAPError as error:
        print(f"feide_check: {error}", file=sys.stderr)
        return 2
    for name, index in seen.items():
        for value, dns in sorted(index.items()):
            if len(dns) > 1:
                for dn in sorted(dns):
                    feide_check_report(dn, name, "Duplicate value in attribute: " + name, value, users)
    for message in sorted(users):
        print(f"TOTAL\t{len(users[message])}\t{message}")
    for message in sorted(skipped):
        print(f"TOTAL\t{skipped[message]}\t{message}")
    return 1 if users else 0


if __name__ == "__main__":
    sys.exit(feide_check_main(sys.argv[1:]))
