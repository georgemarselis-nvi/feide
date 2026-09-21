#!/usr/bin/python3
# feide_check.py
# Checks the user entries of an LDAP directory for the attribute errors reported by the Feide customer portal.
#
# run it as:
#
#   /usr/bin/python3 scripts/feide_check.py --uri ldap://dc01.dfo.no --base DC=dfo,DC=no --realm dfo.no
#
# Assumption: Feide does not publish its mobile check; this script accepts only +47 followed by eight digits.
# Assumption: norEduPersonLegalName is built from givenName plus sn, so its whitespace errors are reported under those two attributes.
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
import ldap.sasl
from ldap.controls import SimplePagedResultsControl

FEIDE_CHECK_WHITESPACE_ATTRS = ("cn", "displayName", "givenName", "mail", "sn", "postalAddress")
FEIDE_CHECK_WHITESPACE_RE = re.compile(r"^\s|\s$|\s{2,}")
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


def feide_check_entry(entry, args):
    errors = []
    attrs = {name.lower(): [value.decode("utf-8", errors="replace") for value in values] for name, values in entry.items()}
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
    for value in attrs.get("mobile", []):
        if not FEIDE_CHECK_MOBILE_RE.match(value):
            errors.append(("mobile", "mobile contains an invalid Norwegian phone number", value))
    return errors


def feide_check_main(argv):
    args = feide_check_parse_args(argv)
    attrs = [args.eppn_attr, args.uid_attr, "mobile"] + list(FEIDE_CHECK_WHITESPACE_ATTRS)
    users = collections.defaultdict(set)
    try:
        conn = feide_check_connect(args.uri)
        for dn, entry in feide_check_search(conn, args.base, args.filter, attrs, args.page_size):
            for attr, message, value in feide_check_entry(entry, args):
                print(f"{dn}\t{attr}\t{message}\t{value!r}")
                users[message].add(dn)
        conn.unbind_s()
    except ldap.LDAPError as error:
        print(f"feide_check: {error}", file=sys.stderr)
        return 2
    for message in sorted(users):
        print(f"TOTAL\t{len(users[message])}\t{message}")
    return 1 if users else 0


if __name__ == "__main__":
    sys.exit(feide_check_main(sys.argv[1:]))
