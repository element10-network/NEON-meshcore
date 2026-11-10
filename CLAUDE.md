# NEON-meshcore: notes for Claude

- The secured MeshCore radio of the Neon Network; the design is in `docs/MESHCORE.md` of
  `element10-network/NEON` ("The secured radio"). The atom's side (flashing, registration, reports)
  lives in NEON's `neond`.
- Commit and push directly to `main` (the owner's preference). No feature branches or PRs unless asked.
- Before pushing: `./build.sh` must succeed (PlatformIO). Change MeshCore's own files only through
  `neon/companion_radio.patch` (regenerate it with `git diff` in `build/MeshCore`), keep the pin in
  `MESHCORE_COMMIT`.
- Never commit keys (`*.pem`). The firmware key is a GitHub secret (`NEON_FIRMWARE_KEY`) of the Radio workflow, used only by its signing job (owner 2026-11-10). Never flash a Heltec with a
  bootloader signed by any other key: the first start burns that key's digest for good.
- Mark anything not yet confirmed on a real Heltec with **(verify)**.
- Always give the owner full, copy-paste commands joined with `&&`, one line per machine.
