// What claiming the free anchor actually decides, separated from the HTTP shell so it can be
// driven directly (tests/deno/trial_license_test.ts).
//
// The rules here guard a paying customer's key, which lives in the same `profiles.license_key`
// column the Polar webhook owns. A bug in this file does not fail loudly: it silently replaces a
// subscriber's key with a free-plan one, and the first they hear of it is their anchoring
// stopping with "not included in the free plan" on a plan they are paying for.
import { mintLicense } from "../_shared/license-mint.ts";

// A trial key verifies for a year. It is not a subscription, so there is no renewal event to
// refresh it, and a key that expires in a month would silently rot for anyone who signed up and
// came back later. The single anchor it can buy is enforced by the anchor service counting rows,
// not by this expiry, so a long life costs nothing.
export const TRIAL_SECONDS = 365 * 24 * 60 * 60;

export type ClaimResult = { body: Record<string, unknown>; status: number };

export type Profile = { plan?: string | null; license_key?: string | null } | null;

/**
 * Decide what a signed-in visitor gets. `now` is unix seconds, passed in rather than read so the
 * expiry is a value a test can assert on rather than a moving target.
 */
export async function claimTrial(
  userId: string,
  profile: Profile,
  now: number,
  store: (key: string) => Promise<{ ok: boolean }>,
): Promise<ClaimResult> {
  const plan = String(profile?.plan ?? "free");
  // A paying customer already holds a better key. Handing them a trial key here would overwrite
  // it in the column the webhook owns, downgrading a subscription by accident.
  if (plan !== "free") {
    return { body: { error: "your plan already includes anchoring", plan }, status: 409 };
  }
  // Idempotent: clicking twice returns the same key rather than minting a second one. The anchor
  // count is what limits the free anchor, so re-issuing would grant nothing, but a key that
  // changes on every click is a key nobody can trust they activated.
  if (profile?.license_key) {
    return { body: { key: profile.license_key, plan: "free", reissued: true }, status: 200 };
  }

  const exp = now + TRIAL_SECONDS;
  const key = await mintLicense(userId, "free", exp);
  if (!key) return { body: { error: "key issuing is not configured" }, status: 503 };

  // Returning a key that was not stored would leave the account page showing nothing on the next
  // visit, and the visitor holding a key this service does not know it issued.
  const written = await store(key);
  if (!written.ok) return { body: { error: "could not record the trial key" }, status: 500 };

  return { body: { key, plan: "free", expires_at: exp }, status: 200 };
}
