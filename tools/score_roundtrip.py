#!/usr/bin/env python3
# Score a round-trip: compare matcher output against ground-truth symbols.
import sys, struct, subprocess, collections

unstripped = sys.argv[1]   # binary WITH symbols (ground truth)
nsig       = sys.argv[2]   # the signature DB
matched    = sys.argv[3]   # matcher output: "addrhex len from name" (from==lib)
guard_names = sys.argv[4].split(",") if len(sys.argv) > 4 else []

# ---- ground truth: addr -> set of function names (aliases share an addr) ----
gt = collections.defaultdict(set)
gt_addrs = set()
out = subprocess.check_output(["nm", unstripped]).decode("utf-8", "replace")
for line in out.splitlines():
    parts = line.split()
    if len(parts) < 3: continue
    addr, typ, name = parts[0], parts[1], " ".join(parts[2:])
    if typ in ("T", "t", "W", "w", "i", "I"):   # include STT_GNU_IFUNC (nm shows 'i')
        try: a = int(addr, 16)
        except ValueError: continue
        gt[a].add(name)
        gt_addrs.add(a)

# ---- DB names (non-ambiguous records only) ----
db = open(nsig, "rb").read()
assert db[:8] == b"NOCTSIG1", "bad magic"
ver, count, flags, resv = struct.unpack_from("<IIII", db, 8)
p = 24
db_names = set()
db_ambig_names = set()
for _ in range(count):
    arch, plen, rflags, nvar = db[p], db[p+1], db[p+2], db[p+3]
    total_len, full_crc, pmask = struct.unpack_from("<III", db, p+4)
    name_len = struct.unpack_from("<H", db, p+48)[0]
    p += 50 + nvar*6
    name = db[p:p+name_len].decode("utf-8", "replace"); p += name_len
    if rflags & 1: db_ambig_names.add(name)
    else: db_names.add(name)

# ---- matcher output ----
named = {}   # addr -> matched name
for line in open(matched):
    parts = line.split()
    if len(parts) < 4: continue
    if parts[2] != "lib": continue
    named[int(parts[0], 16)] = " ".join(parts[3:])

# ---- present / coverable: gt functions whose name set meets a DB name ----
present = 0
for a, names in gt.items():
    if names & db_names:
        present += 1

# ---- classify each named function ----
correct = wrong = spurious = 0
wrong_examples = []
for a, mname in named.items():
    if a not in gt_addrs:
        spurious += 1
        wrong_examples.append((hex(a), mname, "<no gt func at addr>"))
        continue
    if mname in gt[a]:
        correct += 1
    else:
        wrong += 1
        wrong_examples.append((hex(a), mname, "/".join(sorted(gt[a]))[:60]))

named_total = len(named)
recall = correct / present if present else 0.0
precision = correct / named_total if named_total else 0.0

print("=== round-trip score ===")
print(f"DB: {count} records ({len(db_names)} distinct non-ambiguous names, {len(db_ambig_names)} ambiguous)")
print(f"ground-truth function addrs: {len(gt_addrs)}")
print(f"PRESENT (gt funcs whose name is in DB, i.e. coverable): {present}")
print(f"NAMED (matcher assigned a lib name): {named_total}")
print(f"  CORRECT (name matches a gt symbol at that addr): {correct}")
print(f"  WRONG   (name disagrees with gt at that addr):   {wrong}   <-- must be ~0")
print(f"  SPURIOUS(named an addr gt has no function at):   {spurious}   <-- must be ~0")
print(f"MISSED (present - correct): {present - correct}")
print(f"precision = correct/named   = {precision:.4f}")
print(f"recall    = correct/present = {recall:.4f}")
if wrong_examples:
    print("--- wrong/spurious examples (up to 20) ---")
    for a, mn, gtn in wrong_examples[:20]:
        print(f"  {a}: matched={mn}  gt={gtn}")

# ---- guard: the program's own unique functions must NOT be named ----
if guard_names:
    print("--- false-positive guard on the program's own functions ---")
    name_to_addr = {}
    for a, names in gt.items():
        for nm in names: name_to_addr[nm] = a
    for g in guard_names:
        a = name_to_addr.get(g)
        if a is None:
            print(f"  {g}: (not found in gt)")
        else:
            print(f"  {g} @ {hex(a)}: {'NAMED as '+named[a]+'  <-- FALSE POSITIVE' if a in named else 'left SUB_ (correct)'}")
