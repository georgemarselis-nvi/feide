# Dockerfile
#
# OpenLDAP proxy for FEIDE: presents Active Directory to Sikt with the
# norEdu schema, holds no user data and no secrets of its own.
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
# Everything the container needs to know arrives at run time:
#
#   /etc/feide/.env            filled by scripts/orchestrator.sh on the host
#   /etc/krb5.keytab           machine keytab from scripts/join-domain.sh
#   /etc/openldap/certs/       certificate and key from certbot on the host
#
# The entrypoint reads .env, fills the slapd.conf and organisation
# entry templates, prints the settings it is running with, starts
# feide_people.py (which answers for ou=people over back-sock) and
# starts slapd on LDAPS only.
#
# Red Hat does not ship openldap-servers in RHEL 9 itself; it comes
# from EPEL 9, which is why EPEL is enabled below.

FROM registry.access.redhat.com/ubi9/ubi:9.6

LABEL org.opencontainers.image.title="feide-ldap-proxy"
LABEL org.opencontainers.image.description="OpenLDAP proxy presenting Active Directory to FEIDE with the norEdu schema"
LABEL org.opencontainers.image.source="https://github.com/georgemarselis-nvi/feide"
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"

RUN /usr/bin/dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
RUN /usr/bin/dnf install -y openldap-servers openldap-clients cyrus-sasl-gssapi krb5-workstation gettext python3 python3-ldap
RUN /usr/bin/dnf clean all

# Kerberos: slapd runs as the ldap user and binds to Active Directory
# over SASL GSSAPI. With a client keytab set, libkrb5 fetches its own
# ticket from the keytab and renews it; no kinit, no ccache to manage.
ENV KRB5_CLIENT_KTNAME=/etc/krb5.keytab

# eduPerson and SCHAC come from REFEDS at build time, pinned to a commit
# and checked against a SHA-256 sum, so a changed upstream file stops the
# build instead of slipping in. OpenLDAP ships neither.
ARG EDUPERSON_URL=https://raw.githubusercontent.com/REFEDS/eduperson/c672bc4be5e081cba95013b1ac1f7e18fd247ca1/schema/openldap/eduperson.schema
ARG EDUPERSON_SHA256=c6247977be7f1ac89fcac18cb640be87dfdb149cdad6eb94cd10bbfa7614e891
ARG SCHAC_URL=https://raw.githubusercontent.com/REFEDS/SCHAC/9858cc3cea51fb2bba09d8ba5bde1ef14f2d193d/schema/schac.schema
ARG SCHAC_SHA256=0311da58d6824b7cae52411acfd88e8d5cdd3da7ec094f13a6ff1b6b22b68219
RUN /usr/bin/curl -fsSL -o /etc/openldap/schema/eduperson.schema "$EDUPERSON_URL"
RUN /usr/bin/echo "$EDUPERSON_SHA256  /etc/openldap/schema/eduperson.schema" | /usr/bin/sha256sum -c -
RUN /usr/bin/curl -fsSL -o /etc/openldap/schema/schac.schema "$SCHAC_URL"
RUN /usr/bin/echo "$SCHAC_SHA256  /etc/openldap/schema/schac.schema" | /usr/bin/sha256sum -c -

# eduOrg schema (from Stanford's public puppet ldap module, since REFEDS
# publishes none), the norEdu schema converted from the LDIF Sikt
# delivered, plus the templates the entrypoint fills.
COPY schema/eduorg.schema /etc/openldap/schema/eduorg.schema
COPY schema/52-noredu.ldif /etc/openldap/schema/52-noredu.ldif
COPY schema/noredu.schema /etc/openldap/schema/noredu.schema
COPY config/slapd.conf.template /etc/openldap/slapd.conf.template
COPY schema/org.ldif.template /etc/openldap/org.ldif.template
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY scripts/feide_people.py /usr/local/bin/feide_people.py

# The distro unit starts slapd with cn=config; this image uses a
# generated slapd.conf instead, so the default config tree is removed
# to make sure it is never picked up by mistake.
RUN /usr/bin/rm -rf /etc/openldap/slapd.d
RUN /usr/bin/mkdir -p /etc/feide /etc/openldap/certs /var/run/openldap
RUN /usr/bin/chown -R ldap:ldap /etc/openldap /var/run/openldap /var/lib/ldap
RUN /usr/bin/chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/feide_people.py

VOLUME ["/etc/feide", "/etc/openldap/certs"]

EXPOSE 636

USER ldap

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
