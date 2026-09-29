"""OSI-approved licenses (SPDX ids) accepted for benchmark cases.

The CodeQL CLI may only be used on OSI-licensed open-source code (or for academic research), so
every case must name one of these licenses. Extend the set only with ids that
https://spdx.org/licenses/ marks as "OSI Approved".
"""

OSI_APPROVED: frozenset[str] = frozenset(
    {
        "0BSD",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "Apache-2.0",
        "Artistic-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSL-1.0",
        "CDDL-1.0",
        "EPL-2.0",
        "EUPL-1.2",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "ISC",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MIT",
        "MIT-0",
        "MPL-2.0",
        "UPL-1.0",
        "Unlicense",
        "Zlib",
    }
)
