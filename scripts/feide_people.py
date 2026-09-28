#!/usr/bin/python3
# feide_people.py
# Answers slapd's requests for ou=people over the back-sock socket: reads people live from Active Directory and returns them with the values FEIDE expects.
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
#
# How it fits: slapd owns the LDAPS listener, TLS and the ACLs. For every
# operation under ou=people it opens this program's Unix socket, writes the
# request as plain text (slapd-sock(5)) and relays whatever comes back.
# Nothing is stored here; every answer is read from Active Directory at
# that moment.
#
# Searches: the request filter is translated to Active Directory where an
# attribute has a direct counterpart, only to narrow the Active Directory
# search. The original filter is then evaluated here against the entry as
# FEIDE sees it, because slapd does not test filters for back-sock.
#
# Binds: the DN uid=<name>,ou=people,<base> becomes a simple bind to Active
# Directory as <name>@<domain>, so Active Directory checks the password.
#
# Only accounts whose sAMAccountName matches FEIDE_PEOPLE_ACCOUNT_PATTERN in
# .env (whole name, case ignored; NVI: vi[0-9]{4}) are people. Every other
# account (shared mailboxes, rooms, instruments, admin and service accounts)
# is filtered: searches never return it, a base search on it answers "no
# such object", a bind as it fails, and each time a FILTERED line is logged.
# Accounts listed in FEIDE_PEOPLE_ACCOUNT_BLOCKLIST (optional, space
# separated, case ignored) are filtered the same way even when they match
# the pattern; for NVI vi1576 ("Vikar Resepsjonen"), a shared reception
# account with a person-style name.
# The system user in SIKT_BIND_DN is exempt for binds only.
#
# Only the system user in SIKT_BIND_DN may search. slapd sends the bound DN
# with every request (extensions binddn); any other search is refused before
# Active Directory is contacted. Binds are open, since FEIDE checks each
# user's password on a connection that is not bound yet.
#
# Values Active Directory does not hold in the form FEIDE wants:
#   displayName, cn          "Marselis, George" -> "George Marselis"
#                            "Wasimuddin, NFN" -> "Wasimuddin Wasimuddin"
#   givenName                sn when Active Directory has no givenName
#   norEduPersonLegalName    givenName plus sn
#   eduPersonPrincipalName   userPrincipalName in lower case
#   eduPersonAffiliation     constants from EDUPERSONAFFILIATION in .env
#   eduPersonScopedAffiliation, schacHomeOrganization, eduPersonOrgDN
#                            derived from DOMAIN and BASE_DN
#
# Not returned: userPassword (never), norEduPersonNIN (NVI does not hold it),
# norEduPersonAuthnMethod and norEduPersonServiceAuthnLevel (MFA mechanics
# not settled yet).

import base64
import os
import re
import socketserver
import sys

import ldap
import ldap.dn
import ldap.sasl
from ldap.controls import SimplePagedResultsControl

FEIDE_PEOPLE_AD_USER_FILTER = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
FEIDE_PEOPLE_AD_ATTRS = ["sAMAccountName", "userPrincipalName", "displayName", "givenName", "sn", "mail", "mobile"]
FEIDE_PEOPLE_OBJECTCLASSES = ["top", "person", "organizationalPerson", "inetOrgPerson", "eduPerson", "norEduPerson", "schacContactLocation"]
FEIDE_PEOPLE_PAGE_SIZE = 500

# FEIDE attribute (lower case) -> Active Directory attribute, used only to
# narrow the Active Directory search. Anything not listed is evaluated here.
FEIDE_PEOPLE_FILTER_MAP = {
    "uid": "sAMAccountName",
    "edupersonprincipalname": "userPrincipalName",
    "mail": "mail",
    "givenname": "givenName",
    "sn": "sn",
    "mobile": "mobile",
}

FEIDE_PEOPLE_LDAP_SUCCESS = 0
FEIDE_PEOPLE_LDAP_SIZELIMIT_EXCEEDED = 4
FEIDE_PEOPLE_LDAP_AUTH_METHOD_NOT_SUPPORTED = 7
FEIDE_PEOPLE_LDAP_NO_SUCH_OBJECT = 32
FEIDE_PEOPLE_LDAP_INVALID_CREDENTIALS = 49
FEIDE_PEOPLE_LDAP_INSUFFICIENT_ACCESS = 50
FEIDE_PEOPLE_LDAP_UNAVAILABLE = 52
FEIDE_PEOPLE_LDAP_UNWILLING_TO_PERFORM = 53
FEIDE_PEOPLE_LDAP_OTHER = 80
FEIDE_PEOPLE_AUTH_SIMPLE = 128


def feide_people_log(message):
    print("feide_people: " + message, file=sys.stderr, flush=True)


def feide_people_config():
    config = {}
    for name in ("FEIDE_PEOPLE_SOCKET", "FEIDE_PEOPLE_AD_CA", "AD_SERVER", "DOMAIN", "BASE_DN", "AD_BASE_DN", "EDUPERSONAFFILIATION", "SIKT_BIND_DN", "FEIDE_PEOPLE_ACCOUNT_PATTERN"):
        value = os.environ.get(name, "")
        if not value:
            feide_people_log(name + " is not set")
            sys.exit(1)
        config[name] = value
    config["AFFILIATIONS"] = config["EDUPERSONAFFILIATION"].split()
    config["PEOPLE_DN"] = "ou=people," + config["BASE_DN"]
    config["ACCOUNT_RE"] = re.compile(config["FEIDE_PEOPLE_ACCOUNT_PATTERN"], re.IGNORECASE)
    config["BLOCKLIST"] = {name.lower() for name in os.environ.get("FEIDE_PEOPLE_ACCOUNT_BLOCKLIST", "").split()}
    return config


def feide_people_is_person(config, account):
    return config["ACCOUNT_RE"].fullmatch(account) is not None and account.lower() not in config["BLOCKLIST"]


def feide_people_filtered(operation, account, request):
    feide_people_log("FILTERED %s account=%r binddn=%r base=%r filter=%r" % (operation, account, request.get("binddn", ""), request.get("base", request.get("dn", "")), request.get("filter", "")))


# ---------------------------------------------------------------------------
# Filters (RFC 4515). A parsed filter is a tuple:
#   ("and", [f, ...]) ("or", [f, ...]) ("not", f)
#   ("eq", attr, value) ("ge", attr, value) ("le", attr, value)
#   ("approx", attr, value) ("present", attr)
#   ("sub", attr, initial, [any, ...], final)
#   ("const", True | False | None)   slapd's (?=true), (?=false), (?=undefined)
#   ("unknown",)                     extensible match, never true here
# ---------------------------------------------------------------------------

def feide_people_filter_unescape(text):
    out = bytearray()
    i = 0
    raw = text.encode("utf-8")
    while i < len(raw):
        if raw[i:i + 1] == b"\\":
            out += bytes.fromhex(raw[i + 1:i + 3].decode("ascii"))
            i += 3
        else:
            out += raw[i:i + 1]
            i += 1
    return out.decode("utf-8", errors="replace")


def feide_people_filter_escape(text):
    out = []
    for char in text:
        if char in "\\*()\x00":
            out.append("\\%02x" % ord(char))
        else:
            out.append(char)
    return "".join(out)


def feide_people_filter_parse(text):
    tree, pos = feide_people_filter_parse_at(text, 0)
    if pos != len(text):
        raise ValueError("trailing characters in filter")
    return tree


def feide_people_filter_parse_at(text, pos):
    if text[pos] != "(":
        raise ValueError("filter does not start with (")
    pos += 1
    op = text[pos]
    if op in "&|":
        pos += 1
        children = []
        while text[pos] == "(":
            child, pos = feide_people_filter_parse_at(text, pos)
            children.append(child)
        if text[pos] != ")":
            raise ValueError("unterminated filter list")
        return ("and" if op == "&" else "or", children), pos + 1
    if op == "!":
        child, pos = feide_people_filter_parse_at(text, pos + 1)
        if text[pos] != ")":
            raise ValueError("unterminated not")
        return ("not", child), pos + 1
    end = text.index(")", pos)
    item = text[pos:end]
    return feide_people_filter_item(item), end + 1


def feide_people_filter_item(item):
    if item.startswith("?="):
        return ("const", {"true": True, "false": False}.get(item[2:]))
    equals = item.index("=")
    if equals > 0 and item[equals - 1] in "<>~":
        kind = {">": "ge", "<": "le", "~": "approx"}[item[equals - 1]]
        return (kind, item[:equals - 1].lower(), feide_people_filter_unescape(item[equals + 1:]))
    attr, value = item[:equals], item[equals + 1:]
    if ":" in attr:
        return ("unknown",)
    attr = attr.lower()
    if value == "*":
        return ("present", attr)
    if "*" in value:
        parts = value.split("*")
        return ("sub", attr, feide_people_filter_unescape(parts[0]), [feide_people_filter_unescape(p) for p in parts[1:-1] if p], feide_people_filter_unescape(parts[-1]))
    return ("eq", attr, feide_people_filter_unescape(value))


def feide_people_filter_matches(tree, entry):
    """Three-valued: True, False or None (undefined)."""
    kind = tree[0]
    if kind == "and":
        results = [feide_people_filter_matches(child, entry) for child in tree[1]]
        if False in results:
            return False
        return None if None in results else True
    if kind == "or":
        results = [feide_people_filter_matches(child, entry) for child in tree[1]]
        if True in results:
            return True
        return None if None in results else False
    if kind == "not":
        result = feide_people_filter_matches(tree[1], entry)
        return None if result is None else not result
    if kind == "const":
        return tree[1]
    if kind == "unknown":
        return None
    values = [v.casefold() for v in entry.get(tree[1], [])]
    if kind == "present":
        return bool(values)
    if kind == "sub":
        return any(feide_people_filter_substring(v, tree[2].casefold(), [a.casefold() for a in tree[3]], tree[4].casefold()) for v in values)
    wanted = tree[2].casefold()
    if kind in ("eq", "approx"):
        return wanted in values
    if kind == "ge":
        return any(v >= wanted for v in values)
    return any(v <= wanted for v in values)


def feide_people_filter_substring(value, initial, middle, final):
    if not value.startswith(initial):
        return False
    pos = len(initial)
    for part in middle:
        found = value.find(part, pos)
        if found < 0:
            return False
        pos = found + len(part)
    return value.endswith(final) and len(value) - len(final) >= pos


def feide_people_filter_to_ad(tree):
    """Active Directory filter that selects a superset of the matches, or None for no narrowing."""
    kind = tree[0]
    if kind == "and":
        parts = [p for p in (feide_people_filter_to_ad(child) for child in tree[1]) if p is not None]
        if not parts:
            return None
        return parts[0] if len(parts) == 1 else "(&" + "".join(parts) + ")"
    if kind == "or":
        parts = [feide_people_filter_to_ad(child) for child in tree[1]]
        if not parts or None in parts:
            return None
        return "(|" + "".join(parts) + ")"
    if kind == "not":
        part = feide_people_filter_to_ad(tree[1])
        return None if part is None else "(!" + part + ")"
    if kind in ("const", "unknown"):
        return None
    ad_attr = FEIDE_PEOPLE_FILTER_MAP.get(tree[1])
    if ad_attr is None:
        return None
    if kind == "present":
        return "(" + ad_attr + "=*)"
    if kind == "sub":
        pieces = [feide_people_filter_escape(tree[2])] + [feide_people_filter_escape(p) for p in tree[3]] + [feide_people_filter_escape(tree[4])]
        return "(" + ad_attr + "=" + "*".join(pieces) + ")"
    operator = {"eq": "=", "approx": "=", "ge": ">=", "le": "<="}[kind]
    return "(" + ad_attr + operator + feide_people_filter_escape(tree[2]) + ")"


# ---------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------

def feide_people_display_name(value):
    """ "Marselis, George" -> "George Marselis"; anything without ", " is left alone.
    "Wasimuddin, NFN" (no first name) -> "Wasimuddin Wasimuddin"."""
    if ", " not in value:
        return value
    surname, given = value.split(", ", 1)
    if given == "NFN":
        given = surname
    return given + " " + surname


def feide_people_first(attrs, name):
    values = attrs.get(name, [])
    return values[0] if values else None


def feide_people_build_entry(config, ad):
    """Takes the Active Directory attributes of one user; returns (dn, attrs) with lower-case attribute keys."""
    uid = feide_people_first(ad, "sAMAccountName")
    if uid is None:
        return None
    entry = {"objectclass": list(FEIDE_PEOPLE_OBJECTCLASSES), "uid": [uid]}
    display = feide_people_first(ad, "displayName")
    if display is not None:
        entry["displayname"] = [feide_people_display_name(display)]
        entry["cn"] = [feide_people_display_name(display)]
    given = feide_people_first(ad, "givenName")
    surname = feide_people_first(ad, "sn")
    # A person with one name has it in sn and no givenName; FEIDE requires
    # both, so the one name fills both.
    if given is None and surname is not None:
        given = surname
    if given is not None:
        entry["givenname"] = [given]
    if surname is not None:
        entry["sn"] = [surname]
    if given is not None and surname is not None:
        entry["noredupersonlegalname"] = [given + " " + surname]
    upn = feide_people_first(ad, "userPrincipalName")
    if upn is not None:
        entry["edupersonprincipalname"] = [upn.lower()]
    for name in ("mail", "mobile"):
        if ad.get(name):
            entry[name] = list(ad[name])
    entry["edupersonaffiliation"] = list(config["AFFILIATIONS"])
    entry["edupersonscopedaffiliation"] = [a + "@" + config["DOMAIN"] for a in config["AFFILIATIONS"]]
    entry["edupersonorgdn"] = [config["BASE_DN"]]
    entry["schachomeorganization"] = [config["DOMAIN"]]
    return "uid=" + uid + "," + config["PEOPLE_DN"], entry


def feide_people_people_entry(config):
    return config["PEOPLE_DN"], {"objectclass": ["top", "organizationalUnit"], "ou": ["people"]}


# Output names, since entries are keyed in lower case for filter matching.
FEIDE_PEOPLE_ATTR_NAMES = {
    "objectclass": "objectClass", "uid": "uid", "cn": "cn", "displayname": "displayName",
    "givenname": "givenName", "sn": "sn", "noredupersonlegalname": "norEduPersonLegalName",
    "edupersonprincipalname": "eduPersonPrincipalName", "mail": "mail", "mobile": "mobile",
    "edupersonaffiliation": "eduPersonAffiliation", "edupersonscopedaffiliation": "eduPersonScopedAffiliation",
    "edupersonorgdn": "eduPersonOrgDN", "schachomeorganization": "schacHomeOrganization", "ou": "ou",
}


def feide_people_ldif_line(name, value):
    safe = value.isascii() and value == value.strip() and value[:1] not in (":", "<") and "\n" not in value and "\r" not in value and "\x00" not in value
    if safe:
        return name + ": " + value + "\n"
    return name + ":: " + base64.b64encode(value.encode("utf-8")).decode("ascii") + "\n"


def feide_people_ldif(dn, entry):
    out = [feide_people_ldif_line("dn", dn)]
    for key, values in entry.items():
        for value in values:
            out.append(feide_people_ldif_line(FEIDE_PEOPLE_ATTR_NAMES.get(key, key), value))
    return "".join(out) + "\n"


# ---------------------------------------------------------------------------
# Active Directory
# ---------------------------------------------------------------------------

def feide_people_ad_open(config):
    conn = ldap.initialize("ldaps://" + config["AD_SERVER"])
    conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    conn.set_option(ldap.OPT_REFERRALS, 0)
    conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
    conn.set_option(ldap.OPT_X_TLS_CACERTFILE, config["FEIDE_PEOPLE_AD_CA"])
    conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
    conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
    # Active Directory refuses a GSSAPI bind that negotiates signing or
    # sealing on a connection already protected by TLS; TLS carries it.
    conn.set_option(ldap.OPT_X_SASL_SSF_MAX, 0)
    return conn


def feide_people_ad_search(config, ad_filter, limit):
    """Yields the Active Directory attributes of each enabled user matching ad_filter, as {name: [str]}."""
    search_filter = FEIDE_PEOPLE_AD_USER_FILTER if ad_filter is None else "(&" + FEIDE_PEOPLE_AD_USER_FILTER + ad_filter + ")"
    conn = feide_people_ad_open(config)
    try:
        conn.sasl_interactive_bind_s("", ldap.sasl.gssapi())
        control = SimplePagedResultsControl(True, size=FEIDE_PEOPLE_PAGE_SIZE, cookie=b"")
        count = 0
        while True:
            msgid = conn.search_ext(config["AD_BASE_DN"], ldap.SCOPE_SUBTREE, search_filter, FEIDE_PEOPLE_AD_ATTRS, serverctrls=[control])
            _, results, _, server_controls = conn.result3(msgid)
            for dn, attrs in results:
                if dn is None:
                    continue
                count += 1
                if limit > 0 and count > limit:
                    return
                yield {name: [v.decode("utf-8", errors="replace") for v in values] for name, values in attrs.items()}
            cookie = b""
            for server_control in server_controls:
                if server_control.controlType == SimplePagedResultsControl.controlType:
                    cookie = server_control.cookie
            if not cookie:
                return
            control.cookie = cookie
    finally:
        conn.unbind_s()


def feide_people_ad_bind(config, uid, password):
    """Returns an LDAP result code for a simple bind to Active Directory as uid@DOMAIN."""
    conn = feide_people_ad_open(config)
    try:
        conn.simple_bind_s(uid + "@" + config["DOMAIN"], password)
        return FEIDE_PEOPLE_LDAP_SUCCESS
    except ldap.INVALID_CREDENTIALS:
        return FEIDE_PEOPLE_LDAP_INVALID_CREDENTIALS
    except (ldap.SERVER_DOWN, ldap.TIMEOUT, ldap.CONNECT_ERROR):
        return FEIDE_PEOPLE_LDAP_UNAVAILABLE
    finally:
        try:
            conn.unbind_s()
        except ldap.LDAPError:
            pass


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

def feide_people_normalize_dn(dn):
    return ldap.dn.dn2str(ldap.dn.str2dn(dn)).lower()


def feide_people_uid_from_dn(config, dn):
    """uid=<name>,ou=people,<base> -> <name>; None for anything else."""
    try:
        parts = ldap.dn.str2dn(dn)
    except ldap.DECODING_ERROR:
        return None
    if len(parts) < 2 or len(parts[0]) != 1 or parts[0][0][0].lower() != "uid":
        return None
    if ldap.dn.dn2str(parts[1:]).lower() != feide_people_normalize_dn(config["PEOPLE_DN"]):
        return None
    return parts[0][0][1]


def feide_people_is_system_user(config, binddn):
    if not binddn:
        return False
    try:
        return feide_people_normalize_dn(binddn) == feide_people_normalize_dn(config["SIKT_BIND_DN"])
    except ldap.DECODING_ERROR:
        return False


def feide_people_result(code, matched="", info=""):
    out = "RESULT\ncode: %d\n" % code
    if matched:
        out += "matched: " + matched + "\n"
    if info:
        out += "info: " + info + "\n"
    return out


def feide_people_search(config, request, write):
    """Writes matching entries and returns (code, matched, count)."""
    base = request.get("base", "")
    scope = int(request.get("scope", "2"))
    limit = int(request.get("sizelimit", "-1"))
    tree = feide_people_filter_parse(request.get("filter", "(objectClass=*)"))
    ad_filter = feide_people_filter_to_ad(tree)
    people_dn = feide_people_normalize_dn(config["PEOPLE_DN"])
    candidates = []

    if feide_people_normalize_dn(base) == people_dn:
        if scope in (ldap.SCOPE_BASE, ldap.SCOPE_SUBTREE):
            candidates.append(feide_people_people_entry(config))
        users = scope in (ldap.SCOPE_ONELEVEL, ldap.SCOPE_SUBTREE)
    else:
        uid = feide_people_uid_from_dn(config, base)
        if uid is None:
            return FEIDE_PEOPLE_LDAP_NO_SUCH_OBJECT, config["PEOPLE_DN"], 0
        if not feide_people_is_person(config, uid):
            feide_people_filtered("SEARCH", uid, request)
            return FEIDE_PEOPLE_LDAP_NO_SUCH_OBJECT, config["PEOPLE_DN"], 0
        # A person entry is a leaf: base and subtree both mean the entry
        # itself, one level means nothing. The entry is looked up without
        # the filter so that "no such entry" and "does not match" differ.
        found = list(feide_people_ad_search(config, "(sAMAccountName=" + feide_people_filter_escape(uid) + ")", 1))
        if not found:
            return FEIDE_PEOPLE_LDAP_NO_SUCH_OBJECT, config["PEOPLE_DN"], 0
        if scope == ldap.SCOPE_ONELEVEL:
            return FEIDE_PEOPLE_LDAP_SUCCESS, "", 0
        built = feide_people_build_entry(config, found[0])
        if built is not None:
            candidates.append(built)
        users = False

    count = 0
    for dn, entry in candidates:
        if feide_people_filter_matches(tree, entry) is True:
            count += 1
            write(feide_people_ldif(dn, entry))
    if users:
        for ad in feide_people_ad_search(config, ad_filter, 0):
            account = feide_people_first(ad, "sAMAccountName") or ""
            if not feide_people_is_person(config, account):
                feide_people_filtered("SEARCH", account, request)
                continue
            built = feide_people_build_entry(config, ad)
            if built is None or feide_people_filter_matches(tree, built[1]) is not True:
                continue
            count += 1
            if limit > 0 and count > limit:
                return FEIDE_PEOPLE_LDAP_SIZELIMIT_EXCEEDED, "", count - 1
            write(feide_people_ldif(*built))
    return FEIDE_PEOPLE_LDAP_SUCCESS, "", count


def feide_people_bind(config, request):
    if request.get("method") != str(FEIDE_PEOPLE_AUTH_SIMPLE):
        return FEIDE_PEOPLE_LDAP_AUTH_METHOD_NOT_SUPPORTED
    password = request.get("cred", "")
    # slapd writes the password raw on one line; a newline or NUL inside it
    # makes the length disagree, and an empty password would be an
    # anonymous bind in Active Directory. Both are refused.
    if not password or str(len(password.encode("utf-8"))) != request.get("credlen"):
        return FEIDE_PEOPLE_LDAP_INVALID_CREDENTIALS
    uid = feide_people_uid_from_dn(config, request.get("dn", ""))
    if uid is None:
        return FEIDE_PEOPLE_LDAP_INVALID_CREDENTIALS
    if not feide_people_is_person(config, uid) and not feide_people_is_system_user(config, request.get("dn", "")):
        feide_people_filtered("BIND", uid, request)
        return FEIDE_PEOPLE_LDAP_INVALID_CREDENTIALS
    return feide_people_ad_bind(config, uid, password)


def feide_people_read_request(rfile):
    """Returns (command, {key: value}); the cred value is kept byte for byte."""
    command = rfile.readline().decode("utf-8", errors="replace").strip()
    request = {}
    while True:
        line = rfile.readline()
        if not line or line == b"\n":
            break
        text = line.decode("utf-8", errors="replace")[:-1] if line.endswith(b"\n") else line.decode("utf-8", errors="replace")
        key, _, value = text.partition(": ")
        if key not in request:
            request[key] = value
    return command, request


class feide_people_handler(socketserver.StreamRequestHandler):

    def handle(self):
        config = self.server.config
        command, request = feide_people_read_request(self.rfile)

        def write(text):
            self.wfile.write(text.encode("utf-8"))

        try:
            if command == "SEARCH" and not feide_people_is_system_user(config, request.get("binddn", "")):
                feide_people_log("SEARCH refused for binddn=%r" % request.get("binddn", ""))
                write(feide_people_result(FEIDE_PEOPLE_LDAP_INSUFFICIENT_ACCESS))
            elif command == "SEARCH":
                code, matched, count = feide_people_search(config, request, write)
                feide_people_log("SEARCH base=%r scope=%s filter=%r code=%d entries=%d" % (request.get("base"), request.get("scope"), request.get("filter"), code, count))
                write(feide_people_result(code, matched))
            elif command == "BIND":
                code = feide_people_bind(config, request)
                feide_people_log("BIND dn=%r code=%d" % (request.get("dn"), code))
                write(feide_people_result(code))
            elif command == "UNBIND":
                return
            else:
                feide_people_log("%s refused, read only" % command)
                write(feide_people_result(FEIDE_PEOPLE_LDAP_UNWILLING_TO_PERFORM, info="read only"))
        except (ValueError, IndexError) as error:
            feide_people_log("%s bad request: %s" % (command, error))
            write(feide_people_result(FEIDE_PEOPLE_LDAP_OTHER, info="bad request"))
        except ldap.LDAPError as error:
            feide_people_log("%s Active Directory error: %s" % (command, error))
            write(feide_people_result(FEIDE_PEOPLE_LDAP_UNAVAILABLE, info="Active Directory unavailable"))


class feide_people_server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def feide_people_main():
    config = feide_people_config()
    path = config["FEIDE_PEOPLE_SOCKET"]
    if os.path.exists(path):
        os.unlink(path)
    server = feide_people_server(path, feide_people_handler)
    os.chmod(path, 0o600)
    server.config = config
    feide_people_log("listening on " + path + " for " + config["PEOPLE_DN"])
    server.serve_forever()


if __name__ == "__main__":
    feide_people_main()
