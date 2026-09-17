// Canonical .nocturneplugin serializer (Node, zero dependencies).
//
// Produces EXACTLY the bytes that Android's org.json `JSONObject.toString(2)`
// yields for the 6-field plugin object, plus a single trailing newline. The app
// signs these bytes and the app + this CI verify over them, so the two
// implementations MUST agree byte-for-byte. See docs/PLUGIN-HUB.md.
//
// Rules:
//   - UTF-8, "\n" newlines, 2-space indent
//   - keys in the fixed order below, and ONLY those keys
//   - '": "' after each key; ',' immediately before the newline between entries
//   - string escaping matches AOSP org.json JSONStringer.string():
//       '"' -> \"   '\' -> \\   '/' -> \/
//       \b \f \n \r \t as short forms
//       other chars <= U+001F -> \u00xx (lowercase hex)
//       everything else (including non-ASCII) emitted raw as UTF-8
//   - exactly one trailing "\n"

export const KEY_ORDER = ["id", "name", "version", "author", "description", "script"];

function esc(s) {
  let out = '"';
  for (const ch of s) {
    const o = ch.codePointAt(0);
    if (ch === '"' || ch === "\\" || ch === "/") out += "\\" + ch;
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (o <= 0x1f) out += "\\u" + o.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

// Returns a Buffer of the canonical UTF-8 bytes for `plugin`.
export function canonical(plugin) {
  for (const k of KEY_ORDER) {
    if (!(k in plugin)) throw new Error("missing key: " + k);
  }
  for (const k of Object.keys(plugin)) {
    if (!KEY_ORDER.includes(k)) throw new Error("unexpected key: " + k);
  }
  const lines = ["{"];
  KEY_ORDER.forEach((k, i) => {
    const comma = i < KEY_ORDER.length - 1 ? "," : "";
    lines.push("  " + esc(k) + ": " + esc(String(plugin[k])) + comma);
  });
  lines.push("}");
  return Buffer.from(lines.join("\n") + "\n", "utf-8");
}
