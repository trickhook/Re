#!/usr/bin/env python3
"""Checks the Kotlin compiler would catch, run before pushing.

CI is the only Kotlin compiler this project has access to and a round trip
costs five minutes, so each rule here exists because a build actually failed
on it once.
"""
import os, re, sys

ROOT = 'app/src/main/java/com/trickhook'
bad = []


def code_positions(t):
    """(index, char) for source outside strings and comments."""
    out = []
    i, n, state = 0, len(t), None
    while i < n:
        c = t[i]
        if state == 'line':
            if c == '\n': state = None
        elif state == 'block':
            if t.startswith('*/', i): state = None; i += 2; continue
        elif state == 'str':
            if c == '\\': i += 2; continue
            if c == '"': state = None
        elif state == 'raw':
            if t.startswith('"""', i): state = None; i += 3; continue
        elif state == 'char':
            if c == '\\': i += 2; continue
            if c == "'": state = None
        else:
            if t.startswith('//', i): state = 'line'; i += 2; continue
            if t.startswith('/*', i): state = 'block'; i += 2; continue
            if t.startswith('"""', i): state = 'raw'; i += 3; continue
            if c == '"': state = 'str'
            elif c == "'": state = 'char'
            else: out.append((i, c))
        i += 1
    return out


for dp, _, fns in os.walk(ROOT):
    for fn in sorted(fns):
        if not fn.endswith('.kt'):
            continue
        p = os.path.join(dp, fn)
        t = open(p, encoding='utf-8').read()

        # 1. brace balance, ignoring strings and comments
        depth = 0
        for idx, c in code_positions(t):
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth < 0:
                    bad.append('%s:%d unbalanced closing brace'
                               % (p, t[:idx].count('\n') + 1))
                    break
        if depth > 0:
            bad.append('%s ends with brace depth %d' % (p, depth))

        # 2. Material icons used without their import
        pat = r'Icons\.(?:Filled|Outlined|Rounded|TwoTone|Sharp|AutoMirrored\.\w+)\.(\w+)'
        for u in set(re.findall(pat, t)):
            imp = r'^import androidx\.compose\.material\.icons\.[\w.]*%s$' % re.escape(u)
            if not re.search(imp, t, re.M):
                bad.append('%s Icons.*.%s used without import' % (p, u))

        # 3. A `var x` compiles to setX()/getX(); a function with that name and
        #    a matching argument count in the same class is a signature clash.
        props = set(re.findall(r'^\s*(?:private\s+)?var\s+(\w+)\b', t, re.M))
        for m in re.finditer(r'^\s*(?:\w+\s+)*fun\s+(set|get)([A-Z]\w*)\s*\(([^)]*)\)', t, re.M):
            prop = m.group(2)[0].lower() + m.group(2)[1:]
            if prop not in props:
                continue
            args = m.group(3).strip()
            nargs = 0 if not args else args.count(',') + 1
            if (m.group(1) == 'set' and nargs == 1) or (m.group(1) == 'get' and nargs == 0):
                bad.append('%s:%d fun %s%s clashes with the accessor of `var %s`'
                           % (p, t[:m.start()].count('\n') + 1, m.group(1), m.group(2), prop))

for b in bad:
    print(b)
print('KOTLIN AUDIT:', 'FAIL (%d)' % len(bad) if bad else 'clean')
sys.exit(1 if bad else 0)
