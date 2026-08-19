// Parse a base64 TimeStampResp with the SAME file the hosted anchor service uses, and print what
// it read. Not a copy of that code: the module itself is imported, so a change to the service's
// parser is a change to what this prints.
import { parseTimestampResponse, timestampRequest, generalizedTimeToIso, derInteger }
  from "../../supabase/functions/anchor/rfc3161.js";

const input = JSON.parse(process.argv[2]);

if (input.token_b64) {
  const der = Uint8Array.from(Buffer.from(input.token_b64, "base64"));
  const out = parseTimestampResponse(der);
  console.log(JSON.stringify(out));
} else if (input.request_for) {
  const digest = Uint8Array.from(Buffer.from(input.request_for, "hex"));
  const nonce = Uint8Array.from(Buffer.from(input.nonce, "hex"));
  console.log(JSON.stringify({ der: Buffer.from(timestampRequest(digest, nonce)).toString("hex") }));
} else if (input.integer) {
  const out = derInteger(Uint8Array.from(Buffer.from(input.integer, "hex")));
  console.log(JSON.stringify({ der: Buffer.from(out).toString("hex") }));
} else if (input.gentime) {
  console.log(JSON.stringify({ iso: generalizedTimeToIso(input.gentime) }));
}
