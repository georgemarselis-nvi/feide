#!/bin/sh
# brreg-lookup.sh
#
# Look up an organisation in Enhetsregisteret by its domain and print
# the legal name and the organisation number as shell assignments.
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
# Brreg matches every field fuzzily, so a domain search can return more
# than one organisation. Exactly one hit on hjemmeside is taken as is.
# Zero or several hits fall back to a name search on the first label of
# the domain and an interactive menu; the orchestrator caches the answer
# in .env so the menu is shown once.
#
# Brreg stores names in upper case. They are converted to title case,
# then the Norwegian words that are not capitalised mid-name are put
# back to lower case.
#
# Usable two ways:
#   - executed directly: prints NAVN and ORGANISASJONSNUMMER as quoted
#     shell assignments on stdout, exit 1 on failure
#   - sourced (". brreg-lookup.sh"): defines the functions below and
#     does nothing else; the caller invokes brreg_lookup itself

set -eu

BRREG_LOOKUP_API="${BRREG_LOOKUP_API:-https://data.brreg.no/enhetsregisteret/api/enheter}"
BRREG_LOOKUP_STOPWORDS="og i for av på til med"

brreg_lookup_usage() {
	echo "usage: $0 <domain>" >&2
	echo "example: $0 dfo.no" >&2
	return 2
}

# Query brreg on one field. Prints the JSON response.
brreg_lookup_fetch() {
	/usr/bin/curl -s --max-time 10 -G "$BRREG_LOOKUP_API" --data-urlencode "$1=$2"
}

brreg_lookup_hit_count() {
	echo "$1" | /usr/bin/jq -r '.page.totalElements'
}

brreg_lookup_field() {
	echo "$1" | /usr/bin/jq -r "._embedded.enheter[0].$2"
}

brreg_lookup_title_case() {
	echo "$1" | /usr/bin/sed -e 's/.*/\L&/' -e 's/\(^\|[ -]\)\([a-zæøå]\)/\1\u\2/g'
}

brreg_lookup_lower_stopwords() {
	name="$1"
	for word in $BRREG_LOOKUP_STOPWORDS; do
		cap=$(echo "$word" | /usr/bin/sed 's/^./\u&/')
		name=$(echo "$name" | /usr/bin/sed "s/ $cap / $word /g")
	done
	echo "$name"
}

brreg_lookup_pretty_name() {
	brreg_lookup_lower_stopwords "$(brreg_lookup_title_case "$1")"
}

# Name search with an interactive menu. Prints "orgnr<TAB>name" on
# stdout; returns 1 on no matches, abort or bad choice.
brreg_lookup_fallback_by_name() {
	keyword="$1"
	fallback=$(brreg_lookup_fetch navn "$keyword")

	names=$(echo "$fallback" | /usr/bin/jq -r '._embedded.enheter[] | .organisasjonsnummer + "\t" + .navn')
	if [ -z "$names" ]; then
		echo "brreg-lookup: no matches for '$keyword' either" >&2
		return 1
	fi

	echo "Matches for '$keyword':" >&2
	echo "$names" | /usr/bin/nl -w2 -s') ' >&2

	printf "Pick a number, or 0 to abort: " >&2
	read -r choice
	if ! [ "$choice" -ge 1 ] 2>/dev/null; then
		echo "brreg-lookup: aborted" >&2
		return 1
	fi

	picked=$(echo "$names" | /usr/bin/sed -n "${choice}p")
	if [ -z "$picked" ]; then
		echo "brreg-lookup: no such choice" >&2
		return 1
	fi

	orgnr=$(echo "$picked" | /usr/bin/cut -f1)
	raw_name=$(echo "$picked" | /usr/bin/cut -f2)
	printf '%s\t%s\n' "$orgnr" "$(brreg_lookup_pretty_name "$raw_name")"
}

# Takes a domain. Prints NAVN and ORGANISASJONSNUMMER as quoted shell
# assignments; returns 1 if the organisation cannot be determined.
brreg_lookup() {
	domain="$1"
	keyword=$(echo "$domain" | /usr/bin/cut -d. -f1)

	response=$(brreg_lookup_fetch hjemmeside "$domain")
	count=$(brreg_lookup_hit_count "$response")

	if [ "$count" -eq 1 ] 2>/dev/null; then
		orgnr=$(brreg_lookup_field "$response" organisasjonsnummer)
		name=$(brreg_lookup_pretty_name "$(brreg_lookup_field "$response" navn)")
	else
		echo "brreg-lookup: $count matches for '$domain' on hjemmeside, falling back to name search" >&2
		picked=$(brreg_lookup_fallback_by_name "$keyword") || return 1
		orgnr=$(echo "$picked" | /usr/bin/cut -f1)
		name=$(echo "$picked" | /usr/bin/cut -f2)
	fi

	echo "NAVN=\"$name\""
	echo "ORGANISASJONSNUMMER=\"$orgnr\""
}

brreg_lookup_main() {
	[ $# -eq 1 ] || { brreg_lookup_usage; exit 2; }
	brreg_lookup "$1" || exit 1
}

# Run main only when executed, not when sourced. POSIX sh has no
# BASH_SOURCE; the portable test is whether $0 names this file.
case "$0" in
	*brreg-lookup.sh) brreg_lookup_main "$@" ;;
esac
