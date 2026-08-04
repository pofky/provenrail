import React from "react";
import { AbsoluteFill, interpolate, Sequence, useCurrentFrame } from "remotion";
import { C, mono, sans } from "../theme";
import { Frame } from "../components/Frame";
import { Browser, Card, OAuthBtn, Pill } from "../components/Browser";
import { Terminal } from "../components/Terminal";
import { buildTimeline } from "../lib";

const GH = (
  <svg width={20} height={20} viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 .5a12 12 0 0 0-3.79 23.4c.6.1.82-.26.82-.58v-2.02c-3.34.72-4.04-1.61-4.04-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.09-.75.08-.73.08-.73 1.2.08 1.84 1.24 1.84 1.24 1.07 1.84 2.81 1.31 3.5 1 .1-.78.42-1.31.76-1.61-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.13-.3-.54-1.52.12-3.18 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 0 1 6 0c2.29-1.55 3.3-1.23 3.3-1.23.66 1.66.25 2.88.12 3.18.77.84 1.23 1.91 1.23 3.22 0 4.61-2.8 5.62-5.48 5.92.43.37.81 1.1.81 2.22v3.29c0 .32.22.69.83.57A12 12 0 0 0 12 .5Z" />
  </svg>
);
const GG = (
  <svg width={20} height={20} viewBox="0 0 24 24">
    <path fill="#4285F4" d="M23.5 12.27c0-.79-.07-1.54-.2-2.27H12v4.51h6.47a5.53 5.53 0 0 1-2.4 3.63v3h3.88c2.27-2.09 3.55-5.17 3.55-8.87Z" />
    <path fill="#34A853" d="M12 24c3.24 0 5.96-1.08 7.95-2.91l-3.88-3a7.2 7.2 0 0 1-10.74-3.78H1.32v3.09A12 12 0 0 0 12 24Z" />
    <path fill="#FBBC05" d="M5.33 14.31a7.2 7.2 0 0 1 0-4.62V6.6H1.32a12 12 0 0 0 0 10.8l4.01-3.09Z" />
    <path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.44-3.44A11.98 11.98 0 0 0 12 0 12 12 0 0 0 1.32 6.6l4.01 3.09A7.2 7.2 0 0 1 12 4.75Z" />
  </svg>
);

const Cursor: React.FC<{ x: number; y: number; clickAt?: number }> = ({ x, y, clickAt }) => {
  const frame = useCurrentFrame();
  const pulse = clickAt != null && frame >= clickAt ? interpolate(frame, [clickAt, clickAt + 14], [0, 1], { extrapolateRight: "clamp" }) : 0;
  return (
    <div style={{ position: "absolute", left: x, top: y, zIndex: 30 }}>
      {pulse > 0 && pulse < 1 ? (
        <div
          style={{
            position: "absolute",
            left: -18,
            top: -18,
            width: 44,
            height: 44,
            borderRadius: 99,
            border: `2px solid ${C.accent}`,
            transform: `scale(${0.4 + pulse})`,
            opacity: 1 - pulse,
          }}
        />
      ) : null}
      <svg width={26} height={26} viewBox="0 0 24 24" fill={C.textHi} stroke={C.bg} strokeWidth="1">
        <path d="M5 3l14 7-6 1.5L9 19 5 3z" />
      </svg>
    </div>
  );
};

const Caption: React.FC<{ index: number; total: number; caption: string; note: string }> = ({ index, total, caption, note }) => {
  const frame = useCurrentFrame();
  const o = interpolate(frame, [0, 12], [0, 1], { extrapolateRight: "clamp" });
  return (
    <div style={{ position: "absolute", left: 64, bottom: 52, maxWidth: 780, display: "flex", gap: 16, opacity: o, transform: `translateY(${(1 - o) * 10}px)` }}>
      <div style={{ fontFamily: mono, fontSize: 15, fontWeight: 500, color: C.accentInk, background: C.accent, borderRadius: 8, padding: "6px 12px", whiteSpace: "nowrap", height: "fit-content" }}>
        STEP {index}/{total}
      </div>
      <div>
        <div style={{ fontSize: 27, fontWeight: 700, color: C.textHi, lineHeight: 1.25 }}>{caption}</div>
        <div style={{ fontSize: 19, color: C.textMid, marginTop: 6, lineHeight: 1.4, fontFamily: sans }}>{note}</div>
      </div>
    </div>
  );
};

const Center: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const frame = useCurrentFrame();
  const o = interpolate(frame, [0, 10], [0, 1], { extrapolateRight: "clamp" });
  return (
    <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", paddingTop: 64, opacity: o }}>
      {children}
    </AbsoluteFill>
  );
};

const ek = (label: string) => (
  <div style={{ fontFamily: mono, fontSize: 14, letterSpacing: "0.1em", textTransform: "uppercase", color: C.textLo, marginBottom: 12 }}>{label}</div>
);

// Plan/status/key block shared by the "account" screens.
const AccountPanel: React.FC<{ plan: string; status: string; active: boolean; showKey?: boolean }> = ({ plan, status, active, showKey }) => (
  <div style={{ width: 720, margin: "0 auto", paddingTop: 34 }}>
    <div style={{ fontFamily: mono, fontSize: 13, letterSpacing: "0.18em", color: C.accent, textTransform: "uppercase" }}>Account</div>
    <div style={{ fontFamily: mono, fontSize: 30, color: C.textHi, margin: "6px 0 20px" }}>Your account</div>
    <Card style={{ marginBottom: 14 }}>
      <Row k="Plan" v={<Pill text={plan} on={active} />} />
      <Row k="Status" v={<span style={{ color: active ? C.ok : C.textMid, fontWeight: 700 }}>{status}</span>} last />
    </Card>
    {showKey ? (
      <Card>
        {ek("Commercial license key")}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, background: C.bg, border: `1px solid ${C.border}`, borderRadius: 10, padding: "12px 14px", fontFamily: mono, fontSize: 17, color: C.textHi }}>
          <span>prl_live_eyJ••••••••••••••••••••••••</span>
          <div style={{ display: "flex", gap: 8 }}>
            <Mini t="Reveal" />
            <Mini t="Copy" />
          </div>
        </div>
      </Card>
    ) : (
      <Card>
        {ek("Subscribe")}
        <Plan name="Builder" price="$29/mo" desc="500k events/mo, RFC 3161 trusted timestamps, proof links" />
        <div style={{ height: 10 }} />
        <Plan name="Team" price="$99/mo" desc="2M events/mo, exports, attestation + evidence packs" />
      </Card>
    )}
  </div>
);

const Row: React.FC<{ k: string; v: React.ReactNode; last?: boolean }> = ({ k, v, last }) => (
  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 0", borderBottom: last ? "none" : `1px solid ${C.border}` }}>
    <span style={{ fontFamily: mono, fontSize: 14, letterSpacing: "0.06em", textTransform: "uppercase", color: C.textLo }}>{k}</span>
    <span style={{ fontSize: 19 }}>{v}</span>
  </div>
);
const Mini: React.FC<{ t: string }> = ({ t }) => (
  <span style={{ fontFamily: mono, fontSize: 13, color: C.textMid, background: C.bg3, border: `1px solid ${C.border}`, borderRadius: 8, padding: "6px 10px" }}>{t}</span>
);
const Plan: React.FC<{ name: string; price: string; desc: string }> = ({ name, price, desc }) => (
  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16, background: C.bg, border: `1px solid ${C.border}`, borderRadius: 12, padding: "14px 16px" }}>
    <div>
      <div style={{ fontWeight: 700, fontSize: 19, color: C.textHi }}>{name}</div>
      <div style={{ color: C.textMid, fontSize: 14, marginTop: 2 }}>{desc}</div>
    </div>
    <div style={{ background: C.accent, color: C.accentInk, fontWeight: 700, borderRadius: 10, padding: "10px 16px", fontSize: 16, whiteSpace: "nowrap" }}>{price}</div>
  </div>
);

const D = { signin: 110, free: 95, subscribe: 110, checkout: 95, active: 120, activate: 200 };
const starts = (() => {
  const o: Record<string, number> = {};
  let c = 0;
  for (const [k, v] of Object.entries(D)) { o[k] = c; c += v; }
  return o;
})();
export const PLANS_DURATION = Object.values(D).reduce((a, b) => a + b, 0) + 30;

const activateSteps = buildTimeline([
  {
    caption: "",
    lines: [
      { kind: "cmd", text: "pr activate prl_live_eyJhY2NvdW50Ijoi..." },
      { kind: "out", text: "License valid: builder tier (no expiry).", tone: "ok" },
      { kind: "out", text: "Verified offline, nothing was sent anywhere.", tone: "dim" },
      { kind: "out", text: "`pr serve` now runs at the builder tier.", tone: "default" },
    ],
  },
]);

export const PlansLicensing: React.FC = () => {
  return (
    <Frame eyebrow="Tutorial 03" title="Plans & licensing">
      <Sequence from={starts.signin} durationInFrames={D.signin}>
        <Center>
          <Browser url="provenrail.com/account">
            <div style={{ width: 460, margin: "0 auto", paddingTop: 56 }}>
              <div style={{ fontFamily: mono, fontSize: 13, letterSpacing: "0.18em", color: C.accent, textTransform: "uppercase" }}>Account</div>
              <div style={{ fontFamily: mono, fontSize: 30, color: C.textHi, margin: "6px 0 6px" }}>Sign in</div>
              <div style={{ color: C.textMid, fontSize: 16, marginBottom: 18 }}>No passwords. Continue with GitHub or Google.</div>
              <Card>
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  <OAuthBtn label="Continue with GitHub" icon={GH} />
                  <OAuthBtn label="Continue with Google" icon={GG} />
                </div>
              </Card>
            </div>
          </Browser>
          <Cursor x={1015} y={470} clickAt={80} />
        </Center>
        <Caption index={1} total={6} caption="Sign in at provenrail.com/account" note="One click with GitHub or Google. No password to manage." />
      </Sequence>

      <Sequence from={starts.free} durationInFrames={D.free}>
        <Center>
          <Browser url="provenrail.com/account">
            <AccountPanel plan="free" status="No active subscription" active={false} />
          </Browser>
        </Center>
        <Caption index={2} total={6} caption="You start on the Free plan" note="10k events/mo, full hash-chain integrity, the open-source verifier. No card." />
      </Sequence>

      <Sequence from={starts.subscribe} durationInFrames={D.subscribe}>
        <Center>
          <Browser url="provenrail.com/account">
            <AccountPanel plan="free" status="No active subscription" active={false} />
          </Browser>
          <Cursor x={1010} y={560} clickAt={82} />
        </Center>
        <Caption index={3} total={6} caption="Pick a tier, e.g. Builder" note="Builder unlocks RFC 3161 trusted timestamps, proof links and a live badge." />
      </Sequence>

      <Sequence from={starts.checkout} durationInFrames={D.checkout}>
        <Center>
          <Browser url="polar.sh/checkout/provenrail">
            <div style={{ width: 460, margin: "0 auto", paddingTop: 70, textAlign: "center" }}>
              <div style={{ fontFamily: mono, fontSize: 13, letterSpacing: "0.18em", color: C.accent, textTransform: "uppercase" }}>Polar — secure checkout</div>
              <div style={{ fontSize: 30, fontWeight: 700, color: C.textHi, margin: "12px 0 4px" }}>Builder — $29/mo</div>
              <div style={{ color: C.textMid, fontSize: 15, marginBottom: 22 }}>Merchant of Record. Tax handled. Cancel anytime.</div>
              <Card>
                <div style={{ height: 48, borderRadius: 10, border: `1px solid ${C.border}`, background: C.bg, display: "flex", alignItems: "center", padding: "0 14px", color: C.textLo, fontSize: 15, marginBottom: 12 }}>4242 4242 4242 4242</div>
                <div style={{ height: 52, borderRadius: 10, background: C.accent, color: C.accentInk, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18 }}>Pay $29.00</div>
              </Card>
            </div>
          </Browser>
          <Cursor x={1010} y={500} clickAt={70} />
        </Center>
        <Caption index={4} total={6} caption="Pay through Polar" note="You never hand card data to us, Polar is the Merchant of Record." />
      </Sequence>

      <Sequence from={starts.active} durationInFrames={D.active}>
        <Center>
          <Browser url="provenrail.com/account">
            <AccountPanel plan="builder" status="Active" active showKey />
          </Browser>
        </Center>
        <Caption index={5} total={6} caption="Plan is active, key issued" note="Your commercial license key appears, masked. Reveal or copy it." />
      </Sequence>

      <Sequence from={starts.activate} durationInFrames={D.activate}>
        <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", paddingTop: 70 }}>
          <Terminal timeline={activateSteps} />
        </AbsoluteFill>
        <Caption index={6} total={6} caption="Activate it on your self-hosted server" note="pr activate verifies the key offline. pr serve then runs at your tier." />
      </Sequence>
    </Frame>
  );
};
