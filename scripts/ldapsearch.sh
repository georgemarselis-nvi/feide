#!/usr/bin/bash
# ldapsearch.sh
# Shows the Active Directory entries of every account in a feide_scanner.py output.
#
# Usage:
#   ldapsearch.sh scanner-output.txt
#   scripts/feide_scanner.py --uri ldap://dc02.vetinst.no --account-pattern 'vi[0-9]{4}' | ldapsearch.sh

LDAPSEARCH_OPTIONS=(-LLL -H ldap://dc02.vetinst.no -Y GSSAPI -b OU=VI,DC=vetinst,DC=no)
LDAPSEARCH_ATTRIBUTES=(sAMAccountName displayName givenName sn mail userPrincipalName mobile telephoneNumber otherMobile info description accountExpires lastLogonTimestamp whenCreated)
LDAPSEARCH_INPUT="${1:-/dev/stdin}"

/usr/bin/awk -F'\t' '{ for (i = 1; i <= NF; i++) if ($i ~ /^CN=/) { split($i, dn, ","); sub(/^CN=/, "", dn[1]); print dn[1] } }' "$LDAPSEARCH_INPUT" | /usr/bin/sort -uf | while read -r account; do
    /usr/bin/ldapsearch "${LDAPSEARCH_OPTIONS[@]}" "(&(objectCategory=person)(objectClass=user)(sAMAccountName=${account}))" "${LDAPSEARCH_ATTRIBUTES[@]}"
done
