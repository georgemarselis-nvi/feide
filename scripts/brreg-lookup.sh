#!/bin/sh
# brreg-lookup.sh
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
# Looks up an organisation in Enhetsregisteret by its domain and prints
# the legal name and the organisation number.
#
# Brreg matches every field fuzzily, so a domain search can return more
# than one organisation. Exactly one hit is required; zero or several
# exit nonzero rather than picking.
#
# Brreg stores names in upper case. They are converted to title case,
# then the Norwegian words that are not capitalised mid-name are put
# back to lower case.

set -eu

BRREG_API="https://data.brreg.no/enhetsregisteret/api/enheter"
STOPWORDS="og i for av på til med"

usage() {
	echo "usage: $0 <domain>" >&2
	exit 2
}

fetch() {
	curl -s --max-time 10 -G "$BRREG_API" --data-urlencode "hjemmeside=$1"
}

hit_count() {
	echo "$1" | jq -r '.page.totalElements'
}

field() {
	echo "$1" | jq -r "._embedded.enheter[0].$2"
}

title_case() {
	echo "$1" | sed -e 's/.*/\L&/' -e 's/\(^\|[ -]\)\([a-zæøå]\)/\1\u\2/g'
}

lower_stopwords() {
	name="$1"
	for word in $STOPWORDS; do
		cap=$(echo "$word" | sed 's/^./\u&/')
		name=$(echo "$name" | sed "s/ $cap / $word /g")
	done
	echo "$name"
}

main() {
	[ $# -eq 1 ] || usage
	domain="$1"

	response=$(fetch "$domain")
	count=$(hit_count "$response")

	if [ "$count" -ne 1 ]; then
		echo "brreg-lookup: $count matches for '$domain', need exactly 1" >&2
		exit 1
	fi

	orgnr=$(field "$response" organisasjonsnummer)
	raw_name=$(field "$response" navn)
	name=$(lower_stopwords "$(title_case "$raw_name")")

	echo "NAVN=\"$name\""
	echo "ORGANISASJONSNUMMER=\"$orgnr\""
}

main "$@"
