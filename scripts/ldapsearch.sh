#!/bin/sh
# ldapsearch.sh
#
# Show the Active Directory entries behind a feide_scanner.py run, one
# ldapsearch per account.
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
# The account is taken from the CN= field of every finding line,
# including NEW and GONE lines; each account is searched once.
#
# Requires a valid Kerberos ticket (kinit).
#
# Usable two ways:
#   - executed directly: reads the scanner output from the file given
#     as the third argument, or from stdin, and prints the entries
#   - sourced (". ldapsearch.sh"): defines the functions below and
#     does nothing else; the caller invokes ldapsearch_accounts itself

set -eu

LDAPSEARCH_ATTRIBUTES="sAMAccountName displayName givenName sn mail userPrincipalName mobile telephoneNumber otherMobile info description accountExpires lastLogonTimestamp whenCreated"

ldapsearch_usage() {
	echo "usage: $0 <ldap-server> <base-dn> [scanner-output]" >&2
	echo "example: $0 dc01.dfo.no OU=DFO,DC=dfo,DC=no scanner-output.txt" >&2
	echo "example: scripts/feide_scanner.py --uri ldap://dc01.dfo.no | $0 dc01.dfo.no OU=DFO,DC=dfo,DC=no" >&2
	return 2
}

# Takes a file (or /dev/stdin) of scanner output. Prints each account
# once, case ignored.
ldapsearch_accounts_in() {
	/usr/bin/awk -F'\t' '{ for (i = 1; i <= NF; i++) if ($i ~ /^CN=/) { split($i, dn, ","); sub(/^CN=/, "", dn[1]); print dn[1] } }' "$1" | /usr/bin/sort -uf
}

# Takes a server, a base DN and a file of scanner output. Prints the
# entry of every account found in it.
ldapsearch_accounts() {
	ldapsearch_accounts_in "$3" | while read -r account; do
		# LDAPSEARCH_ATTRIBUTES is left unquoted on purpose: one word per attribute.
		/usr/bin/ldapsearch -LLL -Q -Y GSSAPI -H "ldap://$1" -b "$2" "(&(objectCategory=person)(objectClass=user)(sAMAccountName=${account}))" $LDAPSEARCH_ATTRIBUTES
	done
}

ldapsearch_main() {
	[ $# -eq 2 ] || [ $# -eq 3 ] || { ldapsearch_usage; exit 2; }
	ldapsearch_accounts "$1" "$2" "${3:-/dev/stdin}"
}

# Run main only when executed, not when sourced. POSIX sh has no
# BASH_SOURCE; the portable test is whether $0 names this file.
case "$0" in
	*ldapsearch.sh) ldapsearch_main "$@" ;;
esac
