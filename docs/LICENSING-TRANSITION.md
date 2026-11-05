# Ryzova Kernel — GPLv3 transition tracking (not an effective license grant)

**Status: proposed new outbound policy, not completed file-level relicensing.**

The project's stated direction is:

1. GPL-3.0-only for eligible, rights-controlled Ryzova-authored source;
2. retention of inherited Plan 9/9front MIT licensing and all file/asset exceptions;
3. optional, separately negotiated commercial licensing **only where the licensor possesses sufficient rights**.

There is **no universal GPLv3 license** covering all files in this repository. The current `main` tree still includes Ryzova files marked `SPDX-License-Identifier: AGPL-3.0-only`. Those files remain under their applicable existing public grants until an authorized file-level migration is completed. Earlier AGPL recipients keep their valid rights for copies already received. Both AGPLv3 and GPLv3 allow commercial use in accordance with their terms; an alternative commercial agreement is not required for ordinary GPL-compliant commercial use.

## Migration gates

- [ ] Inventory Ryzova-authored files, SPDX markers, copyright holders, external contributors and imported snippets. Use `scripts/audit_licenses.py` as one input, not conclusive proof.
- [ ] Confirm sufficient rights/permissions to offer each affected file under GPL-3.0-only. Do not assume all contributions are owned by Ryzova; PR submission and DCO do not transfer copyright.
- [ ] Identify any license-combination, exception, font, firmware or third-party redistribution issues. Preserve original upstream notices and file-specific grants.
- [ ] Review the GPLv3 vs AGPLv3 implications for server-side and networking components; decide the precise inbound contribution terms and any CLA needed for optional commercial relicensing.
- [ ] Add a verified, unmodified copy of the GPL-3.0-only license text to `LICENSES/`; update actual eligible headers and per-file license inventory.
- [ ] Update `LICENSE.md`, `COMMERCIAL-LICENSING.md`, `CONTRIBUTING.md`, `docs/CONTRIBUTOR-LICENSING.md`, badges and CI tests **together** with the verified source migration.
- [ ] Obtain appropriate legal/maintainer review, then publish an accurate transition notice and source commit reference.

Neither a repository badge nor this plan can replace third-party license terms, remove earlier rights, or provide permission for optional proprietary relicensing of contributors' code.

Until the checklist is complete, consult [the current license map](../LICENSE.md) and the file-level notices for the actual terms.
