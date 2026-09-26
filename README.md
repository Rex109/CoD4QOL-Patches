<div align="center">

# 💊 CoD4QOL-Patches

**Automatic offsets & patches for [CoD4QOL](https://github.com/Rex109/CoD4QOL)**

[![Update offsets](https://github.com/Rex109/CoD4QOL-Patches/actions/workflows/update-offsets.yml/badge.svg)](https://github.com/Rex109/CoD4QOL-Patches/actions/workflows/update-offsets.yml)
![CoD4X](https://img.shields.io/badge/CoD4X-21.1%2B-orange)
![Python](https://img.shields.io/badge/python-stdlib%20only-blue)

</div>

## ✨ What is this?

Every time **CoD4X** ships a new client, the addresses CoD4QOL hooks into move around.
This repo **pattern-scans every CoD4X release automatically** and publishes a single JSON file that CoD4QOL downloads at startup.

➡️ Players just open the game. New CoD4X version? CoD4QOL picks up the new offsets on its own.

```
📦 CoD4X release  ──►  🤖 GH Action  ──►  🔍 Pattern Scan  ──►  📄 offsets.json  ──►  🎮 CoD4QOL
```

---

## 🧭 How it works

| Step | What happens |
|:---:|---|
| ⏰ | The workflow runs **every 6 hours**, on every push to `main`, or **manually** from the Actions tab |
| 📥 | Downloads `cod4x_021.dll` from every [CoD4X release](https://github.com/callofduty4x/CoD4x_Client_pub/releases) ≥ **21.3** (cached) |
| 🔍 | For each offset, tries its patterns **in order** and keeps the first one that matches **exactly once** |
| 💾 | Offsets already in `offsets.json` are **cached** — only missing ones get scanned |
| 🩹 | Resolves the manual patches for each version |
| ✅ | Commits the updated `offsets.json` |
| ❌ | If a required offset can't be found, **the run fails** and you get an email |

---

## 📁 Repository layout

```
CoD4QOL-Patches/
├── 🔍 signatures.json     # what to look for (patterns per offset)
├── 🩹 patches.json        # what to write, on which offset, for which versions
├── 📄 offsets.json        # ⚙️ generated — this is what CoD4QOL downloads
├── 🐍 scan.py             # the scanner (Python stdlib only)
├── 📂 local_dlls/         # your non-GitHub builds
└── .github/workflows/
    └── 🤖 update-offsets.yml
```

---

## 🔍 `signatures.json`: finding offsets

Each offset has an **ordered list of patterns**. The first pattern that matches exactly once wins.

```json
{
  "menufps": {
    "patterns": [
      { "pattern": "2B 15 ?? ?? ?? ?? 39 DA 72 26 83 3D", "offset": 8 }
    ]
  },
  "hwnd": {
    "patterns": [
      { "pattern": "55 BA ?? ?? ?? ?? 31 C0 B9 0A 00 00 00", "offset": 2, "type": "deref" }
    ]
  }
}
```

| Field | Default | Meaning |
|---|:---:|---|
| `pattern` | — | Hex bytes, `??` = wildcard |
| `offset` | `0` | Distance from the start of the match to the target |
| `type` | `direct` | `direct` → address of the match · `deref` → reads the absolute address stored there |
| `optional` | `false` | If nothing matches, store `null` instead of failing the build |

### 🔧 A new CoD4X version broke a pattern?

1. The workflow goes 🔴 and tells you which offset failed
2. **Append** a new pattern to that offset's list (don't edit the old ones!)
3. Push → the workflow reruns, only for the missing offset → 🟢

> [!TIP]
> Older versions keep matching their original pattern, and newer versions fall through to the new one. Nothing that already works gets touched.

---

## 🩹 `patches.json`: what to write

Patches are written **by hand** and point at an offset by name.

```json
[
  { "patch": "steam_auth_a",    "offset": "steam_auth_a",    "versions": "*",      "bytes": "90 90" },
  { "patch": "iwd_restriction", "offset": "iwd_restriction", "versions": ">=21.4", "bytes": "EB" }
]
```

| Field | Meaning |
|---|---|
| `patch` | Name CoD4QOL uses with `ApplyPatch` / `RemovePatch` |
| `offset` | Which offset it writes to |
| `versions` | `*` · `21.4` · `>=21.4` · `>21.3` · `<21.4` · `21.2..21.3` · or a list of these |
| `bytes` | Bytes to write (`"EB"`, `"90 90"`, `"\\x90\\x90"`) |
| `at` | *(optional)* extra distance from the offset |

> [!NOTE]
> The original bytes are never stored here. CoD4QOL saves them itself before patching, so `RemovePatch` can restore them.

---

## 📄 `offsets.json`: the published file

```
https://raw.githubusercontent.com/Rex109/CoD4QOL-Patches/main/offsets.json
```

```json
{
  "versions": {
    "57f93656": {
      "version": "21.4",
      "offsets": {
        "safechecks": "0x7B4F0",
        "mousefix": null,
        "hwnd": "0x4410820"
      },
      "patches": {
        "iwd_restriction": [ { "address": "0x30A5D", "bytes": "EB" } ]
      }
    }
  }
}
```

- 🔑 Keyed by the **CRC32** of `cod4x_021.dll`
- 📍 Addresses are **relative** to the CoD4X DLL base (`cod4x_entry + address`)
- 🚫 `null` = not needed on this version, so CoD4QOL skips it

---

## 🖥️ Running locally

The workflow only takes care of **new CoD4X releases**. Anything you change yourself (a new offset, a new pattern) is recomputed locally with one command, then committed together with `offsets.json`.

```bash
python scan.py                          # GitHub releases + local_dlls/, fills in missing offsets
python scan.py --recompute menufps      # scan an offset again on every version, even if stored
python scan.py --recompute all          # scan everything again on every version
python scan.py --rescan                 # verify stored offsets, write nothing
python scan.py --offline                # skip GitHub, only local_dlls/
```

No dependencies, just Python 3. 🐍

### 📂 `local_dlls/`

Builds that aren't on GitHub (**21.1**, **21.2**, the **21.3 installer**) go in `local_dlls/` (git-ignored), named after their version:

```
local_dlls/
├── 21.1.dll
├── 21.2.dll
└── 21.3_installer.dll      # anything after "_" is ignored → 21.3
```

Every local run scans them next to the GitHub releases, so **all** versions get new offsets at once.

### ➕ Adding a new offset

1. Add it to `signatures.json` (use `"optional": true` if it only exists in newer versions)
2. If it needs a patch, add it to `patches.json`
3. `git pull`, then `python scan.py`
4. Commit `signatures.json` + `offsets.json` (+ `patches.json`) together and push

The workflow then finds nothing missing and does nothing.

> [!NOTE]
> `--recompute` never throws away a stored value. If no pattern matches an old build anymore, it keeps the stored value and prints a warning; if a pattern finds a **different** value, it's replaced and printed as `CHANGED`.

---

## 🛟 Offline fallback

Every CoD4QOL release **bundles the latest `offsets.json`**. If a player is offline or GitHub is down, CoD4QOL falls back to the embedded copy.