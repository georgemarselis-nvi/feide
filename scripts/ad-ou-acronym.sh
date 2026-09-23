#!/bin/sh
# ad-ou-acronym.sh
#
# Read an organisational unit name from Active Directory over LDAP with
# GSSAPI and print it as the NOREDUORGACRONYM shell assignment.
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
# No public register records an organisation's internal acronym; the
# only place it exists is the OU structure the organisation itself set
# up in AD.
#
# Requires a valid Kerberos ticket (kinit) or a machine keytab from
# join-domain.sh. Must run on a domain-joined host, never in the
# container: this is a one-time or occasional lookup, not a runtime
# dependency of the proxy.
#
# The base is searched at scope base, not sub, so AD's cross-domain
# referrals (ForestDnsZones, DomainDnsZones, Configuration) are never
# returned and never need suppressing.
#
# Usable two ways:
#   - executed directly: prints NOREDUORGACRONYM as a quoted shell
#     assignment on stdout, exit 1 on failure
#   - sourced (". ad-ou-acronym.sh"): defines the functions below and
#     does nothing else; the caller invokes ad_ou_acronym itself

set -eu

ad_ou_acronym_usage() {
	echo "usage: $0 <ldap-server> <ou-dn>" >&2
	echo "example: $0 dc01.dfo.no OU=DFO,DC=dfo,DC=no" >&2
	return 2
}

# Takes a server and an OU DN. Prints the ou attribute value, or nothing.
ad_ou_acronym_read_ou() {
	/usr/bin/ldapsearch -LLL -Q -Y GSSAPI -H "ldap://$1" -b "$2" -s base ou 2>/dev/null | /usr/bin/awk -F': ' '/^ou:/ {print $2; exit}'
}

# Takes a server and an OU DN. Prints NOREDUORGACRONYM as a quoted shell
# assignment; returns 1 if no ou attribute is found.
ad_ou_acronym() {
	acronym=$(ad_ou_acronym_read_ou "$1" "$2")

	if [ -z "$acronym" ]; then
		echo "ad-ou-acronym: no 'ou' attribute found at $2" >&2
		return 1
	fi

	echo "NOREDUORGACRONYM=\"$acronym\""
}

ad_ou_acronym_main() {
	[ $# -eq 2 ] || { ad_ou_acronym_usage; exit 2; }
	ad_ou_acronym "$1" "$2" || exit 1
}

# Run main only when executed, not when sourced. POSIX sh has no
# BASH_SOURCE; the portable test is whether $0 names this file.
case "$0" in
	*ad-ou-acronym.sh) ad_ou_acronym_main "$@" ;;
esac
