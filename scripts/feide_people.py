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
# that moment. Each request runs in its own thread with its own Active
# Directory connection; nothing shared is changed after start-up.
#
# Searches: the request filter is translated to Active Directory where an
# attribute has a direct counterpart, only to narrow the Active Directory
# search. The original filter is then evaluated here against the entry as
# FEIDE sees it, because slapd does not test filters for back-sock.
#
# Binds: the DN uid=<name>,ou=people,<base> becomes a simple bind to Active
# Directory as <name>@<domain>, so Active Directory checks the password.
# Before that the account is looked up; an account that is not found, is
# disabled or is excluded (below), is refused as if it did not exist, and
# the real reason is logged on the FILTERED line.
#
# Only accounts whose sAMAccountName matches FEIDE_PEOPLE_ACCOUNT_PATTERN in
# .env (whole name, case ignored; for example ab[0-9]{4}) are people. Every
# other account (shared mailboxes, rooms, instruments, admin and service
# accounts) is filtered: searches never return it, a base search on it
# answers "no such object", a bind as it fails, and each time a FILTERED
# line is logged. Accounts listed in FEIDE_PEOPLE_ACCOUNT_BLOCKLIST
# (optional, space separated, case ignored) are filtered the same way even
# when they match the pattern, for example a shared reception account with
# a person-style name.
# The system user in SIKT_BIND_DN is exempt for binds only.
#
# Excluded accounts are filtered the same way, with the reason in the
# FILTERED line, even when they are people:
#   info (Notes) containing "skjulmeg" ("hide me"): the Active Directory
#   administrator keeps the marker, and such accounts must not reach FEIDE;
#   description containing "Ekstern bruker": external users must not log in
#   to FEIDE;
#   accountExpires in the past: the account has expired but is still enabled.
#
# Only the system user in SIKT_BIND_DN may search. slapd sends the bound DN
# with every request (extensions binddn); any other search is refused before
# Active Directory is contacted. Binds are open, since FEIDE checks each
# user's password on a connection that is not bound yet.
#
# Logging: every request is logged on a REQUEST line when it arrives
# (command, binddn, dn, base, scope and filter; never the password) and on
# one more line with its outcome.
#
# Values Active Directory does not hold in the form FEIDE wants:
#   displayName, cn          "Surname, Given" -> "Given Surname"
#                            "Surname, NFN" -> "Surname Surname"
#   givenName                sn when Active Directory has no givenName
#   norEduPersonLegalName    givenName plus sn
#   eduPersonPrincipalName   userPrincipalName in lower case
#   uid, mail                "å", "æ", "ø" and "ö" become "a", "ae", "o" and
#                            "o" (and "Å", "Æ", "Ø", "Ö" become "A", "AE", "O",
#                            "O"), since FEIDE takes ASCII only; any other
#                            non-ASCII character is left as it is and logged
#                            on a NONASCII line
#   eduPersonAffiliation     constants from EDUPERSONAFFILIATION in .env
#   eduPersonScopedAffiliation, schacHomeOrganization, eduPersonOrgDN
#                            derived from DOMAIN and BASE_DN
#   norEduPersonAuthnMethod  one SMS method per mobile number, for FEIDE's
#                            two-factor login by text message:
#                            "urn:mace:feide.no:auth:method:sms +4792345678";
#                            every number is passed on as Active Directory
#                            holds it, so a bad one fails loudly at login
#   norEduPersonServiceAuthnLevel
#                            the same for everyone: two-factor on every
#                            service, "urn:mace:feide.no:spid:all
#                            urn:mace:feide.no:auth:level:fad08:3"
#
# Two-factor is on by default. Started with --disable-two-factor, the
# program sends neither norEduPersonAuthnMethod nor
# norEduPersonServiceAuthnLevel, so FEIDE asks for no second factor;
# --enable-two-factor turns it back on.
#
# Not returned: userPassword (never), norEduPersonNIN (the organisation may
# not hold it).

from __future__ import annotations

import argparse
import base64
import datetime
import os
import re
import socketserver
import sys
from typing import Any, Callable, Iterator, Optional

import ldap
import ldap.dn
import ldap.sasl
from ldap.controls import SimplePagedResultsControl

# Active Directory attributes of one user: name as Active Directory spells it -> values.
AdAttrs = dict[str, list[str]]
# A FEIDE entry: lower-case attribute name -> values.
Entry = dict[str, list[str]]
# A parsed filter, see "Filters" below.
FilterTree = tuple[Any, ...]
# A request from slapd: field name -> value.
Request = dict[str, str]
# Settings read from the environment at start-up.
Config = dict[str, Any]

FEIDE_PEOPLE_AD_PERSON_FILTER: str = "(&(objectCategory=person)(objectClass=user))"
FEIDE_PEOPLE_AD_USER_FILTER: str = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
FEIDE_PEOPLE_AD_ATTRS: list[str] = ["sAMAccountName", "userPrincipalName", "displayName", "givenName", "sn", "mail", "mobile", "info", "description", "accountExpires", "userAccountControl"]
# userAccountControl bit set on a disabled account.
FEIDE_PEOPLE_UAC_DISABLED: int = 0x2
FEIDE_PEOPLE_OBJECTCLASSES: list[str] = ["top", "person", "organizationalPerson", "inetOrgPerson", "eduPerson", "norEduPerson", "schacContactLocation"]
FEIDE_PEOPLE_PAGE_SIZE: int = 500
FEIDE_PEOPLE_HIDE_MARKER: str = "skjulmeg"
FEIDE_PEOPLE_EXTERNAL_MARKER: str = "ekstern bruker"
# accountExpires counts 100 ns intervals since 1601-01-01 UTC; 0 and the
# largest value both mean the account never expires.
FEIDE_PEOPLE_FILETIME_EPOCH: datetime.datetime = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
FEIDE_PEOPLE_FILETIME_NEVER: int = 0x7FFFFFFFFFFFFFFF
FEIDE_PEOPLE_REQUIRED_ENV: tuple[str, ...] = ("FEIDE_PEOPLE_SOCKET", "FEIDE_PEOPLE_AD_CA", "AD_SERVER", "DOMAIN", "BASE_DN", "AD_BASE_DN", "EDUPERSONAFFILIATION", "SIKT_BIND_DN", "FEIDE_PEOPLE_ACCOUNT_PATTERN")
FEIDE_PEOPLE_COMMANDS: tuple[str, ...] = ("SEARCH", "BIND", "UNBIND")
# Norwegian letters, and ö, -> ASCII, for uid and mail, which FEIDE takes in ASCII only.
FEIDE_PEOPLE_ASCII_MAP: dict[int, str] = str.maketrans({"å": "a", "æ": "ae", "ø": "o", "ö": "o", "Å": "A", "Æ": "AE", "Ø": "O", "Ö": "O"})
# FEIDE's two-factor method by text message, followed by the number
# (docs.feide.no/reference/mfa/technical_reqs.html).
FEIDE_PEOPLE_SMS_METHOD: str = "urn:mace:feide.no:auth:method:sms"
# Two-factor for every person on every service, at level 3, the only level
# FEIDE supports today.
FEIDE_PEOPLE_SERVICE_AUTHN_LEVEL: str = "urn:mace:feide.no:spid:all urn:mace:feide.no:auth:level:fad08:3"
# Longest request line accepted from slapd, so a broken peer cannot exhaust memory.
FEIDE_PEOPLE_MAX_LINE: int = 65536

# FEIDE attribute (lower case) -> Active Directory attribute, used only to
# narrow the Active Directory search. Anything not listed is evaluated here.
FEIDE_PEOPLE_FILTER_MAP: dict[str, str] = {
    "uid": "sAMAccountName",
    "edupersonprincipalname": "userPrincipalName",
    "mail": "mail",
    "givenname": "givenName",
    "sn": "sn",
    "mobile": "mobile",
}

FEIDE_PEOPLE_LDAP_SUCCESS: int = 0
FEIDE_PEOPLE_LDAP_PROTOCOL_ERROR: int = 2
FEIDE_PEOPLE_LDAP_SIZELIMIT_EXCEEDED: int = 4
FEIDE_PEOPLE_LDAP_AUTH_METHOD_NOT_SUPPORTED: int = 7
FEIDE_PEOPLE_LDAP_NO_SUCH_OBJECT: int = 32
FEIDE_PEOPLE_LDAP_INVALID_DN_SYNTAX: int = 34
FEIDE_PEOPLE_LDAP_INVALID_CREDENTIALS: int = 49
FEIDE_PEOPLE_LDAP_INSUFFICIENT_ACCESS: int = 50
FEIDE_PEOPLE_LDAP_UNAVAILABLE: int = 52
FEIDE_PEOPLE_LDAP_UNWILLING_TO_PERFORM: int = 53
FEIDE_PEOPLE_LDAP_OTHER: int = 80
FEIDE_PEOPLE_RESULT_CODES: frozenset[int] = frozenset({
    FEIDE_PEOPLE_LDAP_SUCCESS, FEIDE_PEOPLE_LDAP_PROTOCOL_ERROR, FEIDE_PEOPLE_LDAP_SIZELIMIT_EXCEEDED,
    FEIDE_PEOPLE_LDAP_AUTH_METHOD_NOT_SUPPORTED, FEIDE_PEOPLE_LDAP_NO_SUCH_OBJECT, FEIDE_PEOPLE_LDAP_INVALID_DN_SYNTAX,
    FEIDE_PEOPLE_LDAP_INVALID_CREDENTIALS, FEIDE_PEOPLE_LDAP_INSUFFICIENT_ACCESS, FEIDE_PEOPLE_LDAP_UNAVAILABLE,
    FEIDE_PEOPLE_LDAP_UNWILLING_TO_PERFORM, FEIDE_PEOPLE_LDAP_OTHER,
})
FEIDE_PEOPLE_AUTH_SIMPLE: int = 128
# slapd also sends 3 (children); it is answered with no entries, as before.
FEIDE_PEOPLE_SCOPES: tuple[int, ...] = (ldap.SCOPE_BASE, ldap.SCOPE_ONELEVEL, ldap.SCOPE_SUBTREE, 3)


class feide_people_bad_request(ValueError):
    """A request from slapd that cannot be answered as sent."""


def feide_people_log(message: str) -> None:
    """Takes a message; writes it to standard error with the program name,
    flushed at once so lines from different threads do not wait in a
    buffer."""
    print("feide_people: " + message, file=sys.stderr, flush=True)


def feide_people_parse_args(argv: list[str]) -> argparse.Namespace:
    """Takes the command line arguments; returns them parsed. The only
    choice is --enable-two-factor or --disable-two-factor, enabled by
    default; the result is in two_factor."""
    parser = argparse.ArgumentParser(description="Answer slapd's back-sock requests for ou=people from Active Directory.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--enable-two-factor", dest="two_factor", action="store_true", help="send the SMS two-factor method and require two-factor on every service (default)")
    group.add_argument("--disable-two-factor", dest="two_factor", action="store_false", help="send no two-factor attributes, so FEIDE asks for no second factor")
    parser.set_defaults(two_factor=True)
    return parser.parse_args(argv)


def feide_people_config() -> Config:
    """Reads the settings from the environment; returns them checked and
    prepared. Exits with an error line when a setting is missing or does
    not parse."""
    config: Config = {}
    for name in FEIDE_PEOPLE_REQUIRED_ENV:
        value = os.environ.get(name, "")
        if not value:
            feide_people_log(name + " is not set")
            sys.exit(1)
        config[name] = value
    if not os.path.isabs(config["FEIDE_PEOPLE_SOCKET"]):
        feide_people_log("FEIDE_PEOPLE_SOCKET is not an absolute path: " + config["FEIDE_PEOPLE_SOCKET"])
        sys.exit(1)
    for name in ("BASE_DN", "AD_BASE_DN", "SIKT_BIND_DN"):
        try:
            ldap.dn.str2dn(config[name])
        except ldap.DECODING_ERROR:
            feide_people_log(name + " is not a valid DN: " + config[name])
            sys.exit(1)
    try:
        config["ACCOUNT_RE"] = re.compile(config["FEIDE_PEOPLE_ACCOUNT_PATTERN"], re.IGNORECASE)
    except re.error as error:
        feide_people_log("FEIDE_PEOPLE_ACCOUNT_PATTERN is not a valid regular expression: %s" % error)
        sys.exit(1)
    config["AFFILIATIONS"] = config["EDUPERSONAFFILIATION"].split()
    config["PEOPLE_DN"] = "ou=people," + config["BASE_DN"]
    config["PEOPLE_DN_NORMALIZED"] = feide_people_normalize_dn(config["PEOPLE_DN"])
    config["SIKT_BIND_DN_NORMALIZED"] = feide_people_normalize_dn(config["SIKT_BIND_DN"])
    config["BLOCKLIST"] = {name.lower() for name in os.environ.get("FEIDE_PEOPLE_ACCOUNT_BLOCKLIST", "").split()}
    return config


def feide_people_is_person(config: Config, account: str) -> bool:
    """Takes an sAMAccountName; returns True when it matches the account
    pattern in full and is not on the blocklist."""
    return config["ACCOUNT_RE"].fullmatch(account) is not None and account.lower() not in config["BLOCKLIST"]


def feide_people_filetime(value: str) -> Optional[datetime.datetime]:
    """Takes an accountExpires value; returns it as a UTC datetime, or None
    when it means never (0 or the largest value) or is not a number."""
    try:
        ticks = int(value)
    except ValueError:
        return None
    if ticks <= 0 or ticks >= FEIDE_PEOPLE_FILETIME_NEVER:
        return None
    return FEIDE_PEOPLE_FILETIME_EPOCH + datetime.timedelta(microseconds=ticks // 10)


def feide_people_excluded_reason(ad: AdAttrs) -> Optional[str]:
    """Takes the Active Directory attributes of a person; returns why the
    account must not reach FEIDE (disabled, "skjulmeg" in info, "Ekstern
    bruker" in description, or an accountExpires date that has passed), or
    None."""
    try:
        control = int(feide_people_first(ad, "userAccountControl") or "0")
    except ValueError:
        control = 0
    if control & FEIDE_PEOPLE_UAC_DISABLED:
        return "account disabled"
    if any(FEIDE_PEOPLE_HIDE_MARKER in value.lower() for value in ad.get("info", [])):
        return "marked skjulmeg"
    if any(FEIDE_PEOPLE_EXTERNAL_MARKER in value.lower() for value in ad.get("description", [])):
        return "external user"
    expires = feide_people_filetime(feide_people_first(ad, "accountExpires") or "0")
    if expires is not None and expires <= datetime.datetime.now(datetime.timezone.utc):
        return "account expired " + expires.date().isoformat()
    return None


def feide_people_filtered(operation: str, account: str, request: Request, reason: str) -> None:
    """Takes the operation, the account, the request and the reason; logs a
    FILTERED line. The password is never part of it."""
    feide_people_log("FILTERED %s account=%r reason=%r binddn=%r target=%r filter=%r" % (operation, account, reason, request.get("binddn", ""), request.get("base", request.get("dn", "")), request.get("filter", "")))


# ---------------------------------------------------------------------------
# Filters (RFC 4515). A parsed filter is a tuple:
#   ("and", [f, ...]) ("or", [f, ...]) ("not", f)
#   ("eq", attr, value) ("ge", attr, value) ("le", attr, value)
#   ("approx", attr, value) ("present", attr)
#   ("sub", attr, initial, [any, ...], final)
#   ("const", True | False | None)   slapd's (?=true), (?=false), (?=undefined)
#   ("unknown",)                     extensible match, never true here
# ---------------------------------------------------------------------------

def feide_people_filter_unescape(text: str) -> str:
    """Takes a filter value with \\XX escapes; returns it unescaped. Raises
    ValueError for an escape that is not two hex digits."""
    out = bytearray()
    i = 0
    raw = text.encode("utf-8")
    while i < len(raw):
        if raw[i:i + 1] == b"\\":
            pair = raw[i + 1:i + 3]
            if len(pair) != 2:
                raise ValueError("truncated escape in filter")
            out += bytes.fromhex(pair.decode("ascii"))
            i += 3
        else:
            out += raw[i:i + 1]
            i += 1
    return out.decode("utf-8", errors="replace")


def feide_people_filter_escape(text: str) -> str:
    """Takes a value; returns it escaped for use inside an LDAP filter."""
    out: list[str] = []
    for char in text:
        if char in "\\*()\x00":
            out.append("\\%02x" % ord(char))
        else:
            out.append(char)
    return "".join(out)


def feide_people_filter_parse(text: str) -> FilterTree:
    """Takes a filter string; returns the parsed filter. Raises ValueError or
    IndexError for a malformed filter."""
    tree, pos = feide_people_filter_parse_at(text, 0)
    if pos != len(text):
        raise ValueError("trailing characters in filter")
    return tree


def feide_people_filter_parse_at(text: str, pos: int) -> tuple[FilterTree, int]:
    """Takes a filter string and a position at an opening parenthesis;
    returns the filter parsed from there and the position after it."""
    if text[pos] != "(":
        raise ValueError("filter does not start with (")
    pos += 1
    op = text[pos]
    if op in "&|":
        pos += 1
        children: list[FilterTree] = []
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


def feide_people_filter_item(item: str) -> FilterTree:
    """Takes one filter item without parentheses (attr=value and its
    variants); returns it parsed."""
    if item.startswith("?="):
        return ("const", {"true": True, "false": False}.get(item[2:]))
    equals = item.index("=")
    if equals > 0 and item[equals - 1] in "<>~":
        kind = {">": "ge", "<": "le", "~": "approx"}[item[equals - 1]]
        return (kind, item[:equals - 1].lower(), feide_people_filter_unescape(item[equals + 1:]))
    attr, value = item[:equals], item[equals + 1:]
    if not attr:
        raise ValueError("filter item without an attribute")
    if ":" in attr:
        return ("unknown",)
    attr = attr.lower()
    if value == "*":
        return ("present", attr)
    if "*" in value:
        parts = value.split("*")
        return ("sub", attr, feide_people_filter_unescape(parts[0]), [feide_people_filter_unescape(p) for p in parts[1:-1] if p], feide_people_filter_unescape(parts[-1]))
    return ("eq", attr, feide_people_filter_unescape(value))


def feide_people_filter_matches(tree: FilterTree, entry: Entry) -> Optional[bool]:
    """Takes a parsed filter and an entry; returns True, False or None
    (undefined), as LDAP's three-valued filter logic requires."""
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


def feide_people_filter_substring(value: str, initial: str, middle: list[str], final: str) -> bool:
    """Takes a value and the pieces of a substring filter; returns True when
    the value starts with initial, holds the middle pieces in order and ends
    with final, without the pieces overlapping."""
    if not value.startswith(initial):
        return False
    pos = len(initial)
    for part in middle:
        found = value.find(part, pos)
        if found < 0:
            return False
        pos = found + len(part)
    return value.endswith(final) and len(value) - len(final) >= pos


def feide_people_filter_to_ad(tree: FilterTree) -> Optional[str]:
    """Takes a parsed filter; returns an Active Directory filter that selects
    a superset of the matches, or None for no narrowing. >=, <= and ~= are
    never narrowed: Active Directory compares them differently from this
    program, so under a ! the narrowing could drop entries that match."""
    kind = tree[0]
    if kind in ("ge", "le", "approx"):
        return None
    if kind == "and":
        parts = [p for p in (feide_people_filter_to_ad(child) for child in tree[1]) if p is not None]
        if not parts:
            return None
        return parts[0] if len(parts) == 1 else "(&" + "".join(parts) + ")"
    if kind == "or":
        parts_or = [feide_people_filter_to_ad(child) for child in tree[1]]
        if not parts_or or None in parts_or:
            return None
        return "(|" + "".join(part for part in parts_or if part is not None) + ")"
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
    return "(" + ad_attr + "=" + feide_people_filter_escape(tree[2]) + ")"


# ---------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------

def feide_people_display_name(value: str) -> str:
    """Takes an Active Directory displayName; returns it as FEIDE wants it:
    "Surname, Given" -> "Given Surname", "Surname, NFN" (no first name) ->
    "Surname Surname"; anything without ", " is left alone."""
    if ", " not in value:
        return value
    surname, given = value.split(", ", 1)
    if given == "NFN":
        given = surname
    return given + " " + surname


def feide_people_ascii(account: str, name: str, value: str) -> str:
    """Takes the account, the attribute name and a value; returns the value
    with "å", "æ", "ø" and "ö" (either case) turned into "a", "ae", "o" and
    "o". Logs a
    NONASCII line when non-ASCII characters remain, since FEIDE rejects
    them."""
    converted = value.translate(FEIDE_PEOPLE_ASCII_MAP)
    if not converted.isascii():
        feide_people_log("NONASCII account=%r attribute=%s value=%r" % (account, name, converted))
    return converted


def feide_people_authn_methods(mobiles: list[str]) -> list[str]:
    """Takes the mobile numbers of an account; returns one SMS two-factor
    method value per number, with the number exactly as Active Directory
    holds it. A badly formatted number is not hidden: the person's
    two-factor login fails and they report it, and the scanner reports it
    too."""
    return [FEIDE_PEOPLE_SMS_METHOD + " " + value for value in mobiles]


def feide_people_first(attrs: AdAttrs, name: str) -> Optional[str]:
    """Takes attributes and a name; returns the first value, or None."""
    values = attrs.get(name, [])
    return values[0] if values else None


def feide_people_build_entry(config: Config, ad: AdAttrs) -> Optional[tuple[str, Entry]]:
    """Takes the Active Directory attributes of one user; returns (DN, entry)
    with lower-case attribute keys, or None when the user has no
    sAMAccountName."""
    account = feide_people_first(ad, "sAMAccountName")
    if account is None:
        return None
    uid = feide_people_ascii(account, "uid", account)
    entry: Entry = {"objectclass": list(FEIDE_PEOPLE_OBJECTCLASSES), "uid": [uid]}
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
    if ad.get("mail"):
        entry["mail"] = [feide_people_ascii(account, "mail", value) for value in ad["mail"]]
    if ad.get("mobile"):
        entry["mobile"] = list(ad["mobile"])
        if config["TWO_FACTOR"]:
            entry["noredupersonauthnmethod"] = feide_people_authn_methods(ad["mobile"])
    entry["edupersonaffiliation"] = list(config["AFFILIATIONS"])
    entry["edupersonscopedaffiliation"] = [a + "@" + config["DOMAIN"] for a in config["AFFILIATIONS"]]
    entry["edupersonorgdn"] = [config["BASE_DN"]]
    entry["schachomeorganization"] = [config["DOMAIN"]]
    if config["TWO_FACTOR"]:
        entry["noredupersonserviceauthnlevel"] = [FEIDE_PEOPLE_SERVICE_AUTHN_LEVEL]
    return "uid=" + ldap.dn.escape_dn_chars(uid) + "," + config["PEOPLE_DN"], entry


def feide_people_people_entry(config: Config) -> tuple[str, Entry]:
    """Takes the configuration; returns (DN, entry) for ou=people itself."""
    return config["PEOPLE_DN"], {"objectclass": ["top", "organizationalUnit"], "ou": ["people"]}


# Output names, since entries are keyed in lower case for filter matching.
FEIDE_PEOPLE_ATTR_NAMES: dict[str, str] = {
    "objectclass": "objectClass", "uid": "uid", "cn": "cn", "displayname": "displayName",
    "givenname": "givenName", "sn": "sn", "noredupersonlegalname": "norEduPersonLegalName",
    "edupersonprincipalname": "eduPersonPrincipalName", "mail": "mail", "mobile": "mobile",
    "edupersonaffiliation": "eduPersonAffiliation", "edupersonscopedaffiliation": "eduPersonScopedAffiliation",
    "edupersonorgdn": "eduPersonOrgDN", "schachomeorganization": "schacHomeOrganization", "ou": "ou",
    "noredupersonauthnmethod": "norEduPersonAuthnMethod",
    "noredupersonserviceauthnlevel": "norEduPersonServiceAuthnLevel",
}


def feide_people_ldif_line(name: str, value: str) -> str:
    """Takes an attribute name and value; returns one LDIF line, base64
    encoded whenever the value is not safe as plain text."""
    safe = value.isascii() and value == value.strip() and value[:1] not in (":", "<") and "\n" not in value and "\r" not in value and "\x00" not in value
    if safe:
        return name + ": " + value + "\n"
    return name + ":: " + base64.b64encode(value.encode("utf-8")).decode("ascii") + "\n"


def feide_people_ldif(dn: str, entry: Entry) -> str:
    """Takes a DN and an entry; returns the entry as LDIF, ending in a blank
    line. Only attributes FEIDE is meant to see are written."""
    out: list[str] = [feide_people_ldif_line("dn", dn)]
    for key, values in entry.items():
        name = FEIDE_PEOPLE_ATTR_NAMES.get(key)
        if name is None:
            continue
        for value in values:
            out.append(feide_people_ldif_line(name, value))
    return "".join(out) + "\n"


# ---------------------------------------------------------------------------
# Active Directory
# ---------------------------------------------------------------------------

def feide_people_ad_open(config: Config) -> ldap.ldapobject.LDAPObject:
    """Takes the configuration; returns an unbound LDAPS connection to Active
    Directory that checks the server certificate against the configured
    CA."""
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


def feide_people_ad_search(config: Config, ad_filter: Optional[str], limit: int, include_disabled: bool = False) -> Iterator[AdAttrs]:
    """Takes the configuration, an extra Active Directory filter (or None), a
    limit (0 for none) and whether disabled users count; yields the
    attributes of each user that matches, one page at a time. Searches over
    all people return enabled users only."""
    people = FEIDE_PEOPLE_AD_PERSON_FILTER if include_disabled else FEIDE_PEOPLE_AD_USER_FILTER
    search_filter = people if ad_filter is None else "(&" + people + ad_filter + ")"
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


def feide_people_ad_lookup(config: Config, uid: str) -> Optional[AdAttrs]:
    """Takes an sAMAccountName; returns the attributes of that user, enabled
    or not, so the caller can log the real reason for a refusal, or None
    when Active Directory has no user by that name."""
    found = list(feide_people_ad_search(config, "(sAMAccountName=" + feide_people_filter_escape(uid) + ")", 1, include_disabled=True))
    return found[0] if found else None


def feide_people_ad_bind(config: Config, uid: str, password: str) -> int:
    """Takes an sAMAccountName and a password; returns the LDAP result code of
    a simple bind to Active Directory as uid@DOMAIN."""
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

def feide_people_normalize_dn(dn: str) -> str:
    """Takes a DN; returns it in canonical lower-case form. Raises
    ldap.DECODING_ERROR for a DN that does not parse."""
    return ldap.dn.dn2str(ldap.dn.str2dn(dn)).lower()


def feide_people_uid_from_dn(config: Config, dn: str) -> Optional[str]:
    """Takes a DN; returns <name> for uid=<name>,ou=people,<base>, or None
    for anything else, including a DN that does not parse."""
    try:
        parts = ldap.dn.str2dn(dn)
    except ldap.DECODING_ERROR:
        return None
    if len(parts) < 2 or len(parts[0]) != 1 or parts[0][0][0].lower() != "uid":
        return None
    if ldap.dn.dn2str(parts[1:]).lower() != config["PEOPLE_DN_NORMALIZED"]:
        return None
    return parts[0][0][1]


def feide_people_is_system_user(config: Config, binddn: str) -> bool:
    """Takes a bind DN; returns True when it is the Sikt system user."""
    if not binddn:
        return False
    try:
        return feide_people_normalize_dn(binddn) == config["SIKT_BIND_DN_NORMALIZED"]
    except ldap.DECODING_ERROR:
        return False


def feide_people_result(code: int, matched: str = "", info: str = "") -> str:
    """Takes a result code, a matched DN and a message; returns the RESULT
    block slapd expects. Raises ValueError for a code this program does not
    use, and drops line breaks from matched and info so they cannot break
    the block."""
    if code not in FEIDE_PEOPLE_RESULT_CODES:
        raise ValueError("unexpected result code %d" % code)
    out = "RESULT\ncode: %d\n" % code
    if matched:
        out += "matched: " + matched.replace("\n", " ").replace("\r", " ") + "\n"
    if info:
        out += "info: " + info.replace("\n", " ").replace("\r", " ") + "\n"
    return out


def feide_people_int_field(request: Request, name: str, default: int) -> int:
    """Takes a request, a field name and a default; returns the field as an
    integer. Raises feide_people_bad_request when it is not a number."""
    text = request.get(name, str(default))
    try:
        return int(text)
    except ValueError:
        raise feide_people_bad_request("%s is not a number: %r" % (name, text)) from None


def feide_people_search(config: Config, request: Request, write: Callable[[str], None]) -> tuple[int, str, int]:
    """Takes a SEARCH request and a writer; writes the matching entries as
    LDIF and returns (code, matched DN, number of entries written)."""
    base = request.get("base", "")
    scope = feide_people_int_field(request, "scope", ldap.SCOPE_SUBTREE)
    if scope not in FEIDE_PEOPLE_SCOPES:
        raise feide_people_bad_request("unsupported scope %d" % scope)
    limit = feide_people_int_field(request, "sizelimit", -1)
    tree = feide_people_filter_parse(request.get("filter", "(objectClass=*)"))
    ad_filter = feide_people_filter_to_ad(tree)
    try:
        base_normalized = feide_people_normalize_dn(base)
    except ldap.DECODING_ERROR:
        return FEIDE_PEOPLE_LDAP_INVALID_DN_SYNTAX, "", 0
    candidates: list[tuple[str, Entry]] = []

    if base_normalized == config["PEOPLE_DN_NORMALIZED"]:
        if scope in (ldap.SCOPE_BASE, ldap.SCOPE_SUBTREE):
            candidates.append(feide_people_people_entry(config))
        users = scope in (ldap.SCOPE_ONELEVEL, ldap.SCOPE_SUBTREE)
    else:
        uid = feide_people_uid_from_dn(config, base)
        if uid is None:
            return FEIDE_PEOPLE_LDAP_NO_SUCH_OBJECT, config["PEOPLE_DN"], 0
        if not feide_people_is_person(config, uid):
            feide_people_filtered("SEARCH", uid, request, "not a person")
            return FEIDE_PEOPLE_LDAP_NO_SUCH_OBJECT, config["PEOPLE_DN"], 0
        # A person entry is a leaf: base and subtree both mean the entry
        # itself, one level means nothing. The entry is looked up without
        # the filter so that "no such entry" and "does not match" differ.
        ad = feide_people_ad_lookup(config, uid)
        if ad is None:
            feide_people_filtered("SEARCH", uid, request, "no such account")
            return FEIDE_PEOPLE_LDAP_NO_SUCH_OBJECT, config["PEOPLE_DN"], 0
        reason = feide_people_excluded_reason(ad)
        if reason is not None:
            feide_people_filtered("SEARCH", uid, request, reason)
            return FEIDE_PEOPLE_LDAP_NO_SUCH_OBJECT, config["PEOPLE_DN"], 0
        if scope == ldap.SCOPE_ONELEVEL:
            return FEIDE_PEOPLE_LDAP_SUCCESS, "", 0
        built = feide_people_build_entry(config, ad)
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
                feide_people_filtered("SEARCH", account, request, "not a person")
                continue
            reason = feide_people_excluded_reason(ad)
            if reason is not None:
                feide_people_filtered("SEARCH", account, request, reason)
                continue
            built = feide_people_build_entry(config, ad)
            if built is None or feide_people_filter_matches(tree, built[1]) is not True:
                continue
            count += 1
            if limit > 0 and count > limit:
                return FEIDE_PEOPLE_LDAP_SIZELIMIT_EXCEEDED, "", count - 1
            write(feide_people_ldif(*built))
    return FEIDE_PEOPLE_LDAP_SUCCESS, "", count


def feide_people_bind(config: Config, request: Request) -> int:
    """Takes a BIND request; returns the LDAP result code. Only simple binds
    as uid=<name>,ou=people,<base> are accepted. A person is looked up in
    Active Directory first; one that is not found, or is excluded, gets
    invalid credentials, as if the account did not exist. The system user
    skips the lookup."""
    if request.get("method") != str(FEIDE_PEOPLE_AUTH_SIMPLE):
        return FEIDE_PEOPLE_LDAP_AUTH_METHOD_NOT_SUPPORTED
    password = request.get("cred", "")
    # slapd writes the password raw on one line; a newline or NUL inside it
    # makes the length disagree, and an empty password would be an
    # anonymous bind in Active Directory. Both are refused.
    if not password or str(len(password.encode("utf-8"))) != request.get("credlen"):
        return FEIDE_PEOPLE_LDAP_INVALID_CREDENTIALS
    dn = request.get("dn", "")
    uid = feide_people_uid_from_dn(config, dn)
    if uid is None:
        return FEIDE_PEOPLE_LDAP_INVALID_CREDENTIALS
    if feide_people_is_system_user(config, dn):
        return feide_people_ad_bind(config, uid, password)
    if not feide_people_is_person(config, uid):
        feide_people_filtered("BIND", uid, request, "not a person")
        return FEIDE_PEOPLE_LDAP_INVALID_CREDENTIALS
    ad = feide_people_ad_lookup(config, uid)
    if ad is None:
        feide_people_filtered("BIND", uid, request, "no such account")
        return FEIDE_PEOPLE_LDAP_INVALID_CREDENTIALS
    reason = feide_people_excluded_reason(ad)
    if reason is not None:
        feide_people_filtered("BIND", uid, request, reason)
        return FEIDE_PEOPLE_LDAP_INVALID_CREDENTIALS
    return feide_people_ad_bind(config, uid, password)


def feide_people_read_request(rfile: Any) -> tuple[str, Request]:
    """Takes the socket's read side; returns (command, {field: value}). The
    cred value is kept byte for byte. Raises feide_people_bad_request for a
    line longer than FEIDE_PEOPLE_MAX_LINE."""
    first = rfile.readline(FEIDE_PEOPLE_MAX_LINE + 1)
    if len(first) > FEIDE_PEOPLE_MAX_LINE:
        raise feide_people_bad_request("request line too long")
    command = first.decode("utf-8", errors="replace").strip()
    request: Request = {}
    while True:
        line = rfile.readline(FEIDE_PEOPLE_MAX_LINE + 1)
        if len(line) > FEIDE_PEOPLE_MAX_LINE:
            raise feide_people_bad_request("request line too long")
        if not line or line == b"\n":
            break
        text = line.decode("utf-8", errors="replace")[:-1] if line.endswith(b"\n") else line.decode("utf-8", errors="replace")
        key, _, value = text.partition(": ")
        if key not in request:
            request[key] = value
    return command, request


def feide_people_describe(command: str, request: Request) -> str:
    """Takes a command and its request; returns the fields worth logging.
    The password (cred) is never included."""
    fields = ("binddn", "dn", "base", "scope", "filter")
    return " ".join("%s=%r" % (name, request[name]) for name in fields if name in request)


class feide_people_handler(socketserver.StreamRequestHandler):
    """Answers one request from slapd on one connection."""

    def handle(self) -> None:
        """Reads the request, logs it, answers it and logs the outcome."""
        config: Config = self.server.config

        def write(text: str) -> None:
            """Takes text; sends it to slapd as UTF-8."""
            self.wfile.write(text.encode("utf-8"))

        try:
            command, request = feide_people_read_request(self.rfile)
        except feide_people_bad_request as error:
            feide_people_log("REQUEST unreadable: %s" % error)
            write(feide_people_result(FEIDE_PEOPLE_LDAP_PROTOCOL_ERROR, info="bad request"))
            return
        feide_people_log("REQUEST %s %s" % (command or "<empty>", feide_people_describe(command, request)))

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
                feide_people_log("UNBIND binddn=%r" % request.get("binddn", ""))
                return
            else:
                feide_people_log("%s refused, read only" % (command or "<empty>"))
                write(feide_people_result(FEIDE_PEOPLE_LDAP_UNWILLING_TO_PERFORM, info="read only"))
        except (ValueError, IndexError) as error:
            feide_people_log("%s bad request: %s" % (command, error))
            write(feide_people_result(FEIDE_PEOPLE_LDAP_PROTOCOL_ERROR, info="bad request"))
        except ldap.LDAPError as error:
            feide_people_log("%s Active Directory error: %s" % (command, error))
            write(feide_people_result(FEIDE_PEOPLE_LDAP_UNAVAILABLE, info="Active Directory unavailable"))


class feide_people_server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """Unix socket server that answers each connection in its own thread."""
    daemon_threads: bool = True
    config: Config


def feide_people_main() -> None:
    """Reads the command line and the configuration, opens the socket
    readable by its owner only and serves requests until the process is
    stopped."""
    args = feide_people_parse_args(sys.argv[1:])
    config = feide_people_config()
    config["TWO_FACTOR"] = args.two_factor
    path: str = config["FEIDE_PEOPLE_SOCKET"]
    if os.path.exists(path):
        os.unlink(path)
    server = feide_people_server(path, feide_people_handler)
    os.chmod(path, 0o600)
    server.config = config
    feide_people_log("listening on " + path + " for " + config["PEOPLE_DN"] + ", two-factor " + ("on" if config["TWO_FACTOR"] else "off"))
    server.serve_forever()


if __name__ == "__main__":
    feide_people_main()
