// Verify a license key with the SAME file the hosted anchor service uses. Not a copy: the module
// is imported, so a change to the service's verifier changes what this prints.
import { verifyLicense } from "../../supabase/functions/anchor/license.js";

const { token, pub, now } = JSON.parse(process.argv[2]);
console.log(JSON.stringify(await verifyLicense(token, pub, now)));
