#!/bin/sh
# ad-ou-acronym.sh
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
# Reads an organisational unit name from Active Directory over LDAP
# using GSSAPI, for use as the norEduOrgAcronym value. No public
# register records an organisation's internal acronym; the only place
# it exists is the OU structure the organisation itself set up in AD.
#
# Requires a valid Kerberos ticket (kinit) or a machine keytab from
# join-domain.sh. Must run on a domain-joined host, never in the
# container: this is a one-time or occasional lookup, not a runtime
# dependency of the proxy.
#
# The base is searched at scope base, not sub, so AD's cross-domain
# referrals (ForestDnsZones, DomainDnsZones, Configuration) are never
# returned and never need suppressing.

set -eu

usage() {
	echo "usage: $0 <ldap-server> <ou-dn>" >&2
	echo "example: $0 dc02.example.org OU=VI,DC=example,DC=org" >&2
	exit 2
}

main() {
	[ $# -eq 2 ] || usage
	server="$1"
	ou_dn="$2"

	acronym=$(/usr/bin/ldapsearch -LLL -Q -Y GSSAPI -H "ldap://$server" -b "$ou_dn" -s base ou 2>/dev/null \
		| /usr/bin/awk -F': ' '/^ou:/ {print $2; exit}')

	if [ -z "$acronym" ]; then
		echo "ad-ou-acronym: no 'ou' attribute found at $ou_dn" >&2
		exit 1
	fi

	echo "NOREDUORGACRONYM=\"$acronym\""
}

main "$@"
