#!/bin/sh
# orchestrator.sh
#
# Fill .env with the values the FEIDE proxy needs, running only the
# lookups whose answers are still missing.
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Sources the lookup scripts that sit next to it and consults .env for
# each value in turn. A value already present is kept; a missing one is
# looked up and written back, so every lookup runs once and the next
# start is silent. This is what makes brreg-lookup's interactive menu
# acceptable: the operator answers it once.
#
# Values, in the order they are resolved:
#
#   DOMAIN                  discover-domain.sh, from the egress address
#   NAVN                    brreg-lookup.sh, from DOMAIN
#   ORGANISASJONSNUMMER     brreg-lookup.sh, from DOMAIN
#   NOREDUORGSCHEMAVERSION  set by hand; defaults to 2.0 if absent
#   AD_SERVER               from the _ldap._tcp.dc._msdcs SRV record of
#                           DOMAIN; the first domain controller listed
#   AD_OU_DN                set by hand; the OU whose name is the acronym
#   NOREDUORGACRONYM        ad-ou-acronym.sh, from AD_SERVER and AD_OU_DN
#
# Anything that can neither be found in .env nor derived stops the run
# with a message naming the variable to add. Nothing is asked for
# interactively except brreg-lookup's own menu.
#
# The machine keytab is checked last. If it is missing, the run stops
# and tells the operator to run join-domain.sh first; joining a domain
# is provisioning done once by hand, not something this script does.
#
# Ends by printing every value it is running with, the organisation
# number first, since a wrong number breaks service activation in the
# FEIDE customer portal and is the first thing to check.
#
# Usable two ways:
#   - executed directly: fills .env (first argument, default ./.env)
#     and prints the summary, exit 1 on failure
#   - sourced (". orchestrator.sh"): defines the functions below and
#     does nothing else

set -eu

ORCHESTRATOR_DIR=$(/usr/bin/dirname "$0")
ORCHESTRATOR_ENV_FILE="${ORCHESTRATOR_ENV_FILE:-.env}"
ORCHESTRATOR_KEYTAB="${ORCHESTRATOR_KEYTAB:-/etc/krb5.keytab}"
ORCHESTRATOR_DEFAULT_SCHEMA_VERSION="2.0"

orchestrator_usage() {
	echo "usage: $0 [env-file]" >&2
	echo "example: $0 /srv/feide/.env" >&2
	return 2
}

orchestrator_load_scripts() {
	. "$ORCHESTRATOR_DIR/discover-domain.sh"
	. "$ORCHESTRATOR_DIR/brreg-lookup.sh"
	. "$ORCHESTRATOR_DIR/ad-ou-acronym.sh"
}

# Creates the env file if absent and loads what it holds.
orchestrator_load_env() {
	[ -f "$ORCHESTRATOR_ENV_FILE" ] || /usr/bin/touch "$ORCHESTRATOR_ENV_FILE"
	. "$ORCHESTRATOR_ENV_FILE"
}

# Takes a variable name. Returns 0 if it is set and non-empty.
orchestrator_has() {
	eval "[ -n \"\${$1:-}\" ]"
}

# Takes a variable name and a value. Sets it in the shell and in the
# env file, replacing any earlier line for the same name.
orchestrator_set() {
	eval "$1=\"\$2\""
	/usr/bin/sed -i "/^$1=/d" "$ORCHESTRATOR_ENV_FILE"
	echo "$1=\"$2\"" >> "$ORCHESTRATOR_ENV_FILE"
}

# Takes a variable name and a hint. Stops with a message if the value
# is missing and cannot be derived.
orchestrator_require() {
	orchestrator_has "$1" && return 0
	echo "orchestrator: $1 is not set and cannot be derived. Add it to $ORCHESTRATOR_ENV_FILE, for example $1=\"$2\", and run again." >&2
	return 1
}

# Takes a domain. Prints the first domain controller from its SRV
# record, or nothing.
orchestrator_first_dc() {
	/usr/bin/dig +short SRV "_ldap._tcp.dc._msdcs.$1" 2>/dev/null | /usr/bin/sort -n | /usr/bin/awk 'NR==1 {sub(/\.$/, "", $4); print $4}'
}

orchestrator_resolve_domain() {
	orchestrator_has DOMAIN && return 0
	domain=$(discover_domain) || return 1
	orchestrator_set DOMAIN "$domain"
}

orchestrator_resolve_brreg() {
	orchestrator_has NAVN && orchestrator_has ORGANISASJONSNUMMER && return 0
	eval "$(brreg_lookup "$DOMAIN")" || return 1
	orchestrator_set NAVN "$NAVN"
	orchestrator_set ORGANISASJONSNUMMER "$ORGANISASJONSNUMMER"
}

orchestrator_resolve_schema_version() {
	orchestrator_has NOREDUORGSCHEMAVERSION && return 0
	orchestrator_set NOREDUORGSCHEMAVERSION "$ORCHESTRATOR_DEFAULT_SCHEMA_VERSION"
}

orchestrator_resolve_ad_server() {
	orchestrator_has AD_SERVER && return 0
	dc=$(orchestrator_first_dc "$DOMAIN")
	if [ -n "$dc" ]; then
		orchestrator_set AD_SERVER "$dc"
		return 0
	fi
	orchestrator_require AD_SERVER "dc01.$DOMAIN"
}

orchestrator_resolve_acronym() {
	orchestrator_has NOREDUORGACRONYM && return 0
	orchestrator_resolve_ad_server || return 1
	orchestrator_require AD_OU_DN "OU=DFO,DC=dfo,DC=no" || return 1
	eval "$(ad_ou_acronym "$AD_SERVER" "$AD_OU_DN")" || return 1
	orchestrator_set NOREDUORGACRONYM "$NOREDUORGACRONYM"
}

orchestrator_resolve_keytab() {
	[ -f "$ORCHESTRATOR_KEYTAB" ] && return 0
	echo "orchestrator: no keytab at $ORCHESTRATOR_KEYTAB. Run join-domain.sh $DOMAIN as root on this host first, then run again." >&2
	return 1
}

orchestrator_summary() {
	echo
	echo "FEIDE proxy settings ($ORCHESTRATOR_ENV_FILE):"
	echo
	echo "  ORGANISASJONSNUMMER     $ORGANISASJONSNUMMER"
	echo "  NAVN                    $NAVN"
	echo "  NOREDUORGACRONYM        $NOREDUORGACRONYM"
	echo "  DOMAIN                  $DOMAIN"
	echo "  NOREDUORGSCHEMAVERSION  $NOREDUORGSCHEMAVERSION"
	echo "  AD_SERVER               $AD_SERVER"
	echo "  AD_OU_DN                $AD_OU_DN"
	echo "  keytab                  $ORCHESTRATOR_KEYTAB"
	echo
	echo "Check the organisation number against Brønnøysundregisteret before going further."
}

orchestrator() {
	orchestrator_load_scripts
	orchestrator_load_env
	orchestrator_resolve_domain || return 1
	orchestrator_resolve_brreg || return 1
	orchestrator_resolve_schema_version
	orchestrator_resolve_acronym || return 1
	orchestrator_resolve_keytab || return 1
	orchestrator_summary
}

orchestrator_main() {
	[ $# -le 1 ] || { orchestrator_usage; exit 2; }
	[ $# -eq 1 ] && ORCHESTRATOR_ENV_FILE="$1"
	orchestrator || exit 1
}

# Run main only when executed, not when sourced. POSIX sh has no
# BASH_SOURCE; the portable test is whether $0 names this file.
case "$0" in
	*orchestrator.sh) orchestrator_main "$@" ;;
esac
