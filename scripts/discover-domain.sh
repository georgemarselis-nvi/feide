#!/bin/sh
# discover-domain.sh
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
# address: ask an external service for the public IP this host leaves
# the network with, then take the PTR for that address. The host's own
# private address is not used; a container cannot trust local network
# state, and RFC1918 addresses have no public reverse DNS.
#
# The egress address MUST have a reverse DNS entry. If it does not,
# this exits nonzero and the caller aborts. That is deliberate: a
# missing PTR is a network prerequisite the operator has to fix, not
# something to guess around.

set -eu

EGRESS_SERVICE="https://api.ipify.org"

egress_ip() {
	curl -s --max-time 10 "$EGRESS_SERVICE"
}

domain_from_egress() {
	ip=$(egress_ip)
	[ -n "$ip" ] || return 1

	ptr=$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//')
	[ -n "$ptr" ] || return 1

	# Take the last two labels: the TLD and the registrable name.
	echo "$ptr" | awk -F. '{print $(NF-1)"."$NF}'
}

main() {
	if domain=$(domain_from_egress); then
		echo "$domain"
	else
		echo "discover-domain: egress address has no reverse DNS entry; cannot determine domain" >&2
		exit 1
	fi
}

main "$@"
