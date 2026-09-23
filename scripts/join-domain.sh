#!/bin/sh
# join-domain.sh
#
# One-time interactive AD domain join for the host or VM that will run
# this container, using realmd with the sssd backend.
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
# Run this ONCE, by hand, before the container ever starts. It prompts
# for a join password interactively and never writes that password
# anywhere; realm join uses it only for the join operation itself.
# The result is a machine keytab at /etc/krb5.keytab, which is what
# the container mounts afterward. There is nothing here for the
# container to run again on every start: rejoining recreates the
# machine account, so this script is provisioning, not runtime.
#
# Requires: realmd, sssd-ad, sssd-tools, adcli.
#
# Usable two ways:
#   - executed directly: joins the domain, exit 1 on failure
#   - sourced (". join-domain.sh"): defines the functions below and
#     does nothing else; the caller invokes join_domain itself

set -eu

JOIN_DOMAIN_KEYTAB="${JOIN_DOMAIN_KEYTAB:-/etc/krb5.keytab}"

join_domain_usage() {
	echo "usage: $0 <domain>" >&2
	echo "example: $0 dfo.no" >&2
	return 2
}

join_domain_require_root() {
	if [ "$(/usr/bin/id -u)" -ne 0 ]; then
		echo "join-domain: must run as root" >&2
		return 1
	fi
}

# Takes a domain. Joins it and verifies the keytab; returns 1 on failure.
join_domain() {
	domain="$1"

	join_domain_require_root || return 1

	echo "Joining $domain via realmd (sssd backend)."
	echo "You will be prompted for a domain join account and password."
	echo "The password is used once, for this join, and is not stored by this script."

	/usr/sbin/realm join --membership-software=sssd "$domain" || return 1

	if [ -f "$JOIN_DOMAIN_KEYTAB" ]; then
		echo "Join complete. Machine keytab at $JOIN_DOMAIN_KEYTAB."
		echo "Mount this keytab into the container; do not run this script again unless the machine leaves and rejoins the domain."
	else
		echo "join-domain: realm join reported success but $JOIN_DOMAIN_KEYTAB is missing" >&2
		return 1
	fi
}

join_domain_main() {
	[ $# -eq 1 ] || { join_domain_usage; exit 2; }
	join_domain "$1" || exit 1
}

# Run main only when executed, not when sourced. POSIX sh has no
# BASH_SOURCE; the portable test is whether $0 names this file.
case "$0" in
	*join-domain.sh) join_domain_main "$@" ;;
esac
