#!/bin/sh
# join-domain.sh
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
# One-time interactive AD domain join for the host or VM that will run
# this container, using realmd with the sssd backend.
#
# Run this ONCE, by hand, before the container ever starts. It prompts
# for a join password interactively and never writes that password
# anywhere; realm join uses it only for the join operation itself.
# The result is a machine keytab at /etc/krb5.keytab, which is what
# the container mounts afterward. There is nothing here for the
# container to run again on every start: rejoining recreates the
# machine account, so this script is provisioning, not runtime.
#
# Requires: realmd, sssd-ad, sssd-tools, adcli (Debian: apt install
# realmd sssd-ad sssd-tools adcli).

set -eu

usage() {
	echo "usage: $0 <domain>" >&2
	echo "example: $0 dfo.no" >&2
	exit 2
}

require_root() {
	[ "$(id -u)" -eq 0 ] || { echo "join-domain: must run as root" >&2; exit 1; }
}

main() {
	[ $# -eq 1 ] || usage
	domain="$1"

	require_root

	echo "Joining $domain via realmd (sssd backend)."
	echo "You will be prompted for a domain join account and password."
	echo "The password is used once, for this join, and is not stored by this script."

	realm join --membership-software=sssd "$domain"

	if [ -f /etc/krb5.keytab ]; then
		echo "Join complete. Machine keytab at /etc/krb5.keytab."
		echo "Mount this keytab into the container; do not run this script again unless the machine leaves and rejoins the domain."
	else
		echo "join-domain: realm join reported success but /etc/krb5.keytab is missing" >&2
		exit 1
	fi
}

main "$@"
