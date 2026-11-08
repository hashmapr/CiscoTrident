// TRIDENT <-> pt-convert bridge.
//
// This file is TRIDENT's own glue code. It imports the operator's own clone of
// pt-convert (path supplied by TRIDENT_PT_CONVERT_DIR) and executes its exported
// functions: decryptPacket() and simplifyXmlToJson().
//
// pt-convert is All-Rights-Reserved; TRIDENT never copies its source into this
// repository. Running this bridge requires that the operator legitimately has
// that code on disk and permission to execute it.
//
// Usage: node engine_c_bridge.mjs <pt_convert_dir> <input_file>
// Output: a single JSON object on stdout. Errors -> {"error": "..."} + exit 2.

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import path from "node:path";

function fail(message) {
  process.stdout.write(JSON.stringify({ error: message }));
  process.exit(2);
}

const [ptDir, inputFile] = process.argv.slice(2);
if (!ptDir || !inputFile) {
  fail("usage: engine_c_bridge.mjs <pt_convert_dir> <input_file>");
}

const cryptoPath = path.join(ptDir, "src", "lib", "packet-crypto.ts");
const simplifierPath = path.join(ptDir, "src", "lib", "xml-simplifier.ts");

let decryptPacket;
let simplifyXmlToJson;
try {
  ({ decryptPacket } = await import(pathToFileURL(cryptoPath).href));
  ({ simplifyXmlToJson } = await import(pathToFileURL(simplifierPath).href));
} catch (err) {
  fail(`cannot import pt-convert modules from ${ptDir}: ${err.message}`);
}

if (typeof decryptPacket !== "function" || typeof simplifyXmlToJson !== "function") {
  fail("pt-convert modules do not export the expected functions");
}

let bytes;
try {
  bytes = new Uint8Array(readFileSync(inputFile));
} catch (err) {
  fail(`cannot read input: ${err.message}`);
}

let xmlText;
try {
  const xmlBytes = decryptPacket(bytes);
  xmlText = new TextDecoder("utf-8", { fatal: false }).decode(xmlBytes);
} catch (err) {
  fail(`decrypt failed: ${err.message}`);
}

const name = path.basename(inputFile);
const fileType = name.toLowerCase().endsWith(".pka") ? "PKA" : "PKT";

let simplified;
try {
  simplified = simplifyXmlToJson(xmlText, {
    originalFilename: name,
    fileSize: bytes.length,
    fileType,
  });
} catch (err) {
  fail(`simplify failed: ${err.message}`);
}

process.stdout.write(
  JSON.stringify({
    xml_bytes: xmlText.length,
    xml_sha256_input_len: bytes.length,
    // Full decoded XML is passed back so TRIDENT (in Python) applies the ONE
    // shared snapshot-selection policy to the exact bytes pt-convert decoded.
    // pt-convert source is never copied or modified by this.
    xml_text: xmlText,
    devices: simplified.devices ?? {},
    links: simplified.links ?? [],
    metadata: simplified.metadata ?? {},
    activity_instructions: simplified.activityInstructions ?? [],
  }),
);
