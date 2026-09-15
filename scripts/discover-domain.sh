#!/bin/sh
# discover-domain.sh
#
# Find the organisation's domain (for schacHomeOrganization and the
# Feide realm) from the network the host sits on, without trusting
# anything local to the host.
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
# Determines the organisation's domain from the network's egress
# address. Ask an external service for the public IP this host leaves
# the network with, then reverse-look it up. The host's own private
# address is not used; a container cannot trust local network state,
# and RFC1918 addresses have no public reverse DNS.
#
# Two ways to get a domain out of that lookup:
#
#   1. The PTR record of the egress address, if it has one.
#   2. Failing that, the hostname of the DNS server this host is
#      configured to use. dig reports the resolver's IP in its SERVER
#      line; a second reverse lookup turns that into a name. On a
#      correctly set up AD network that resolver is a domain
#      controller and its hostname carries the domain (dc01.vetinst.no).
#
# In both cases the domain is the last two labels of the name.
#
# The egress lookup itself is a hard requirement. If the external
# service returns nothing, this exits nonzero and the caller aborts.
# A missing egress address means the network is not set up for this
# to run, and that is for the operator to fix, not to guess around.
#
# Usable two ways:
#   - executed directly: prints the domain on stdout, exit 1 on failure
#   - sourced (". discover-domain.sh"): defines the functions below and
#     does nothing else; the caller invokes discover_domain itself

set -eu

DISCOVER_DOMAIN_EGRESS_SERVICE="${DISCOVER_DOMAIN_EGRESS_SERVICE:-https://api.ipify.org}"

discover_domain_egress_ip() {
	/usr/bin/curl -s --max-time 10 "$DISCOVER_DOMAIN_EGRESS_SERVICE"
}

# Takes a hostname, prints its last two labels.
discover_domain_last_two_labels() {
	echo "$1" | /usr/bin/awk -F. '{print $(NF-1)"."$NF}'
}

# PTR for an address, or empty.
discover_domain_ptr_of() {
	/usr/bin/dig +short -x "$1" 2>/dev/null | /usr/bin/sed 's/\.$//'
}

# IP of the resolver dig used for a reverse lookup of the address.
discover_domain_resolver_ip() {
	/usr/bin/dig -x "$1" 2>/dev/null | /usr/bin/awk -F'[()]' '/^;; SERVER:/ {print $2; exit}'
}

# Prints the domain on stdout; returns 1 if it cannot be determined.
discover_domain() {
	ip=$(discover_domain_egress_ip)
	[ -n "$ip" ] || return 1

	ptr=$(discover_domain_ptr_of "$ip")
	if [ -n "$ptr" ]; then
		discover_domain_last_two_labels "$ptr"
		return 0
	fi

	resolver=$(discover_domain_resolver_ip "$ip")
	[ -n "$resolver" ] || return 1

	resolver_name=$(discover_domain_ptr_of "$resolver")
	[ -n "$resolver_name" ] || return 1

	discover_domain_last_two_labels "$resolver_name"
}

discover_domain_main() {
	if domain=$(discover_domain); then
		echo "$domain"
	else
		echo "discover-domain: could not determine domain from egress address; no PTR and no resolvable resolver name" >&2
		exit 1
	fi
}

# Run main only when executed, not when sourced. POSIX sh has no
# BASH_SOURCE; the portable test is whether $0 names this file.
case "$0" in
	*discover-domain.sh) discover_domain_main "$@" ;;
esac
