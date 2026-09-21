#!/usr/bin/python3
# feide_check.py
# Checks the user entries of an LDAP directory for the attribute errors reported by the Feide customer portal and for violations of the eduPerson and norEdu schema definitions.
#
# run it as:
#
#   /usr/bin/python3 scripts/feide_check.py --uri ldap://dc01.dfo.no --base DC=dfo,DC=no --realm dfo.no
#
# Assumption: Feide does not publish its mobile check; this script accepts only +47 followed by eight digits.
# Assumption: norEduPersonLegalName is built from givenName plus sn, so its whitespace errors are reported under those two attributes.
# Assumption: the required attribute list (cn, sn, givenName, displayName, eduPersonPrincipalName, mail) is not yet verified against the Feide information model.
# The org unit checks only produce results against the proxy output, since AD holds no eduPerson attributes.
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
import re
import sys

import ldap
import ldap.dn
import ldap.sasl
from ldap.controls import SimplePagedResultsControl

FEIDE_CHECK_WHITESPACE_ATTRS = ("cn", "displayName", "givenName", "mail", "sn", "postalAddress")
FEIDE_CHECK_SINGLE_ATTRS = ("displayName", "givenName", "sn")
FEIDE_CHECK_REQUIRED_ATTRS = ("cn", "sn", "givenName", "displayName", "mail")
FEIDE_CHECK_ORGUNIT_ATTR = "eduPersonOrgUnitDN"
FEIDE_CHECK_PRIMARY_ORGUNIT_ATTR = "eduPersonPrimaryOrgUnitDN"
FEIDE_CHECK_WHITESPACE_RE = re.compile(r"^\s|\s$|\s{2,}")
FEIDE_CHECK_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
FEIDE_CHECK_MOBILE_RE = re.compile(r"^\+47[0-9]{8}$")


def feide_check_parse_args(argv):
    parser = argparse.ArgumentParser(description="Check LDAP user entries against the Feide customer portal attribute rules.")
    parser.add_argument("--uri", required=True, help="LDAP URI, for example ldap://dc01.dfo.no")
    parser.add_argument("--base", required=True, help="search base, for example DC=dfo,DC=no")
    parser.add_argument("--realm", required=True, help="Feide realm (schacHomeOrganization), for example dfo.no")
    parser.add_argument("--filter", default="(&(objectCategory=person)(objectClass=user))", help="search filter for user entries")
    parser.add_argument("--eppn-attr", default="userPrincipalName", help="attribute that becomes eduPersonPrincipalName")
    parser.add_argument("--uid-attr", default="sAMAccountName", help="attribute that becomes uid")
    parser.add_argument("--page-size", type=int, default=500, help="paged search page size")
    return parser.parse_args(argv)


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
        if not FEIDE_CHECK_MOBILE_RE.match(value):
            errors.append(("mobile", "mobile contains an invalid Norwegian phone number", value))
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
    attrs = [args.eppn_attr, args.uid_attr, "mobile", FEIDE_CHECK_ORGUNIT_ATTR, FEIDE_CHECK_PRIMARY_ORGUNIT_ATTR]
    attrs += [name for name in FEIDE_CHECK_WHITESPACE_ATTRS + FEIDE_CHECK_REQUIRED_ATTRS if name not in attrs]
    users = collections.defaultdict(set)
    seen = {args.eppn_attr: collections.defaultdict(set), args.uid_attr: collections.defaultdict(set)}
    cache = {}
    try:
        conn = feide_check_connect(args.uri)
        for dn, entry in feide_check_search(conn, args.base, args.filter, attrs, args.page_size):
            decoded = feide_check_decode(entry)
            for attr, message, value in feide_check_entry(decoded, args) + feide_check_orgunits(conn, decoded, cache):
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
    return 1 if users else 0


if __name__ == "__main__":
    sys.exit(feide_check_main(sys.argv[1:]))
