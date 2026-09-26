"""
Scans CoD4X client DLLs for the offsets listed in signatures.json and
writes offsets.json (offsets + resolved patches per CoD4X build).

  python scan.py                      scan every GitHub release >= MIN_VERSION and every
                                      DLL in local_dlls/, filling in missing offsets
  python scan.py --recompute menufps  scan menufps again on every version, even if stored
  python scan.py --recompute all      scan every offset again on every version
  python scan.py --rescan             re-check cached offsets, write nothing
  python scan.py --offline            skip GitHub, only scan local_dlls/ (and --dll)
  python scan.py --dll path/cod4x_021.dll=21.4
                                      also scan one extra DLL

Only standard library. Exit code 1 if anything needs attention.
"""
import argparse
import json
import os
import re
import struct
import sys
import urllib.request
import zlib

REPO = "callofduty4x/CoD4x_Client_pub"
ASSET = "cod4x_021.dll"
MIN_VERSION = (21, 3)

HERE = os.path.dirname(os.path.abspath(__file__))
SIGNATURES = os.path.join(HERE, "signatures.json")
PATCHES = os.path.join(HERE, "patches.json")
OFFSETS = os.path.join(HERE, "offsets.json")
DLL_DIR = os.path.join(HERE, "dlls")
# DLLs that aren't on GitHub (21.1, 21.2, installer builds...). Name them <version>.dll,
# anything after an underscore is ignored: 21.3_installer.dll -> 21.3
LOCAL_DLL_DIR = os.path.join(HERE, "local_dlls")


# ---------------------------------------------------------------- PE

class PE:
    def __init__(self, data):
        self.data = data
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError("not a PE file")
        nsec, optsize = struct.unpack_from("<H12xH", data, e_lfanew + 6)
        opt = e_lfanew + 24
        self.imagebase = struct.unpack_from("<I", data, opt + 28)[0]
        self.sections = []
        for i in range(nsec):
            o = opt + optsize + i * 40
            name = data[o:o + 8].rstrip(b"\0").decode("latin1")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
            self.sections.append((name, vaddr, vsize, rawptr, rawsize))

    def text(self):
        for name, vaddr, vsize, rawptr, rawsize in self.sections:
            if name == ".text":
                return rawptr, rawptr + rawsize
        raise ValueError("no .text section")

    def off2rva(self, off):
        for _, vaddr, _, rawptr, rawsize in self.sections:
            if rawptr <= off < rawptr + rawsize:
                return off - rawptr + vaddr
        return None


# ---------------------------------------------------------------- patterns

def compile_pattern(text):
    parts = text.split()
    if not parts:
        raise ValueError("empty pattern")
    rx = b""
    for p in parts:
        if p in ("?", "??"):
            rx += b"."
        elif re.fullmatch(r"[0-9A-Fa-f]{2}", p):
            rx += re.escape(bytes([int(p, 16)]))
        else:
            raise ValueError("bad pattern byte %r" % p)
    return re.compile(rx, re.DOTALL)


def find_unique(pe, pattern):
    """File offset of the only match of pattern in .text, or None."""
    lo, hi = pe.text()
    rx = compile_pattern(pattern)
    first = rx.search(pe.data, lo, hi)
    if not first:
        return None
    if rx.search(pe.data, first.start() + 1, hi):
        return None
    return first.start()


def resolve(pe, sig):
    """Try each pattern in order; return (rva, pattern_index) or (None, None)."""
    for i, p in enumerate(sig["patterns"]):
        off = find_unique(pe, p["pattern"])
        if off is None:
            continue
        off += p.get("offset", 0)
        kind = p.get("type", "direct")
        if kind == "direct":
            rva = pe.off2rva(off)
        elif kind == "deref":
            rva = struct.unpack_from("<I", pe.data, off)[0] - pe.imagebase
        else:
            raise ValueError("unknown pattern type %r" % kind)
        if rva is not None and rva > 0:
            return rva, i
    return None, None


# ---------------------------------------------------------------- versions

def parse_version(s):
    m = re.search(r"\d+(?:\.\d+)*", s)
    if not m:
        return None
    return tuple(int(x) for x in m.group().split("."))


def cmp_version(a, b):
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def version_matches(version, spec):
    """spec: "*", "21.3", ">=21.4", ">21.3", "<=21.3", "<21.4", "21.2..21.3", or a list of those."""
    if isinstance(spec, list):
        return any(version_matches(version, s) for s in spec)
    spec = spec.strip()
    v = parse_version(version)
    if spec == "*":
        return True
    if ".." in spec:
        lo, hi = spec.split("..")
        return cmp_version(v, parse_version(lo)) >= 0 and cmp_version(v, parse_version(hi)) <= 0
    for op in (">=", "<=", ">", "<"):
        if spec.startswith(op):
            c = cmp_version(v, parse_version(spec[len(op):]))
            return {">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0}[op]
    return cmp_version(v, parse_version(spec)) == 0


def normalize_bytes(s):
    s = s.replace("\\x", " ").replace(",", " ")
    parts = s.split()
    if len(parts) == 1 and len(parts[0]) > 2:
        parts = re.findall("..", parts[0])
    out = []
    for p in parts:
        if not re.fullmatch(r"[0-9A-Fa-f]{2}", p):
            raise ValueError("bad patch byte %r" % p)
        out.append(p.upper())
    if not out:
        raise ValueError("empty patch bytes")
    return " ".join(out)


# ---------------------------------------------------------------- GitHub

def http_get(url, accept="application/vnd.github+json"):
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "cod4qol-offsets"})
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and "api.github.com" in url:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def github_dlls():
    """[(version, path)] for every release >= MIN_VERSION, downloading what's missing."""
    releases, page = [], 1
    while True:
        batch = json.loads(http_get("https://api.github.com/repos/%s/releases?per_page=100&page=%d" % (REPO, page)))
        releases += batch
        if len(batch) < 100:
            break
        page += 1

    os.makedirs(DLL_DIR, exist_ok=True)
    out = []
    for rel in releases:
        if rel.get("draft") or rel.get("prerelease"):
            continue
        tag = rel["tag_name"]
        v = parse_version(tag)
        if v is None or cmp_version(v, MIN_VERSION) < 0:
            continue
        asset = next((a for a in rel["assets"] if a["name"] == ASSET), None)
        if asset is None:
            print("! release %s has no %s, skipped" % (tag, ASSET))
            continue
        path = os.path.join(DLL_DIR, re.sub(r"[^\w.-]", "_", tag) + ".dll")
        if not os.path.exists(path) or os.path.getsize(path) != asset["size"]:
            print("downloading %s" % tag)
            data = http_get(asset["browser_download_url"], accept="application/octet-stream")
            with open(path, "wb") as f:
                f.write(data)
        out.append((tag, path))
    return out


def local_dlls():
    """[(version, path)] for every DLL in local_dlls/."""
    if not os.path.isdir(LOCAL_DLL_DIR):
        return []
    out = []
    for name in sorted(os.listdir(LOCAL_DLL_DIR)):
        if name.lower().endswith(".dll"):
            out.append((os.path.splitext(name)[0].split("_")[0], os.path.join(LOCAL_DLL_DIR, name)))
    return out


# ---------------------------------------------------------------- main

def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rescan", action="store_true",
                    help="re-resolve cached offsets and fail if any would change; writes nothing")
    ap.add_argument("--recompute", nargs="+", default=[], metavar="OFFSET",
                    help="scan these offsets again even if already stored ('all' for every offset)")
    ap.add_argument("--offline", action="store_true", help="don't query GitHub")
    ap.add_argument("--dll", action="append", default=[], metavar="PATH=VERSION",
                    help="also scan a local DLL")
    args = ap.parse_args()

    sigs = load_json(SIGNATURES, {})
    patches = load_json(PATCHES, [])
    db = load_json(OFFSETS, {"versions": {}})
    versions = db.setdefault("versions", {})

    recompute = set(sigs) if "all" in args.recompute else set(args.recompute)
    unknown = recompute - set(sigs)
    if unknown:
        sys.exit("--recompute: unknown offset(s) %s" % ", ".join(sorted(unknown)))

    errors, warnings = [], []

    # ---- sources
    sources = [] if args.offline else github_dlls()
    sources += local_dlls()
    for item in args.dll:
        path, _, version = item.partition("=")
        if not version:
            sys.exit("--dll needs PATH=VERSION")
        sources.append((version, path))

    # ---- scan
    scanned = set()
    for version, path in sources:
        with open(path, "rb") as f:
            data = f.read()
        crc = "%08x" % (zlib.crc32(data) & 0xFFFFFFFF)
        if crc in scanned:
            continue
        scanned.add(crc)
        pe = PE(data)
        entry = versions.setdefault(crc, {"version": version, "offsets": {}, "patches": {}})
        offs = entry.setdefault("offsets", {})
        print("\n== %s (%s) ==" % (entry["version"], crc))

        for oid, sig in sigs.items():
            cached = offs.get(oid)
            if cached is not None and not args.rescan and oid not in recompute:
                continue

            rva, idx = resolve(pe, sig)

            if oid in recompute and cached is not None and not args.rescan:
                if rva is None:
                    # Hand-verified values on old builds may not match today's patterns
                    warnings.append("%s %s: no pattern matches anymore, kept stored %s"
                                    % (entry["version"], oid, cached))
                    print("  %-38s %s  (kept, no pattern matches)" % (oid, cached))
                    continue
                if rva != int(cached, 16):
                    print("  %-38s %s -> 0x%X  (CHANGED, pattern #%d)" % (oid, cached, rva, idx))
                    offs[oid] = "0x%X" % rva
                    continue

            if args.rescan:
                if cached is not None and rva is not None and rva != int(cached, 16):
                    errors.append("%s %s: cached %s but pattern #%d now gives 0x%X"
                                  % (entry["version"], oid, cached, idx, rva))
                elif cached is None and rva is None and not sig.get("optional"):
                    errors.append("%s %s: not found" % (entry["version"], oid))
                continue

            if rva is None:
                if sig.get("optional"):
                    offs[oid] = None
                    print("  %-38s not found (optional)" % oid)
                else:
                    offs.pop(oid, None)
                    errors.append("%s %s: no pattern matched exactly once" % (entry["version"], oid))
                    print("  %-38s *** NOT FOUND ***" % oid)
            else:
                offs[oid] = "0x%X" % rva
                print("  %-38s 0x%X  (pattern #%d)" % (oid, rva, idx))

    # ---- patches (always rebuilt from patches.json)
    known_ids = set(sigs)
    for entry in versions.values():
        known_ids.update(entry.get("offsets", {}))

    for crc, entry in versions.items():
        offs = entry.get("offsets", {})
        out = {}
        for p in patches:
            if p["offset"] not in known_ids:
                errors.append("patch %s: unknown offset %r" % (p["patch"], p["offset"]))
                continue
            if not version_matches(entry["version"], p["versions"]):
                continue
            value = offs.get(p["offset"])
            if value is None:
                warnings.append("%s: patch %s skipped, offset %s unavailable"
                                % (entry["version"], p["patch"], p["offset"]))
                continue
            out.setdefault(p["patch"], []).append({
                "address": "0x%X" % (int(value, 16) + p.get("at", 0)),
                "bytes": normalize_bytes(p["bytes"]),
            })
        entry["patches"] = out

    # ---- report
    for w in dict.fromkeys(warnings):
        print("warning: " + w)
    for e in dict.fromkeys(errors):
        print("ERROR: " + e)

    if args.rescan:
        print("\nrescan: %s" % ("OK" if not errors else "%d problem(s)" % len(errors)))
        return 1 if errors else 0

    # ---- write (sorted, stable output so git only sees real changes)
    order = list(sigs)
    def sort_offsets(o):
        return {k: o[k] for k in sorted(o, key=lambda k: (order.index(k) if k in order else len(order), k))}

    result = {"versions": {}}
    for crc in sorted(versions, key=lambda c: (parse_version(versions[c]["version"]) or (), c), reverse=True):
        e = versions[crc]
        result["versions"][crc] = {
            "version": e["version"],
            "offsets": sort_offsets(e.get("offsets", {})),
            "patches": e.get("patches", {}),
        }
    with open(OFFSETS, "w", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, indent=2)
        f.write("\n")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
