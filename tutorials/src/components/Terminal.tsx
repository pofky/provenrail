import React from "react";
import { interpolate, useCurrentFrame } from "remotion";
import { C, mono, toneColor } from "../theme";
import { Timeline } from "../lib";

const LINE_H = 40;
const FONT = 23;
const BODY_H = 620; // visible transcript height
const MAX_LINES = Math.floor(BODY_H / LINE_H) - 1; // keep one line of breathing room

const Cursor: React.FC = () => {
  const frame = useCurrentFrame();
  const on = Math.floor(frame / 15) % 2 === 0;
  return (
    <span
      style={{
        display: "inline-block",
        width: 12,
        height: FONT,
        background: on ? C.accent : "transparent",
        transform: "translateY(3px)",
        marginLeft: 2,
      }}
    />
  );
};

export const Terminal: React.FC<{ timeline: Timeline; width?: number }> = ({
  timeline,
  width = 1180,
}) => {
  const frame = useCurrentFrame();

  // Which lines are visible, and the active (currently animating) line index.
  const shown: { idx: number; el: React.ReactNode }[] = [];
  let activeIdx = -1;

  timeline.lines.forEach((ln, idx) => {
    if (frame < ln.start) return;
    activeIdx = idx;

    if (ln.kind === "blank") {
      shown.push({ idx, el: <div style={{ height: LINE_H }} /> });
      return;
    }

    if (ln.kind === "cmd") {
      const prog = ln.typeDur > 0 ? interpolate(frame, [ln.start, ln.start + ln.typeDur], [0, ln.text.length], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }) : ln.text.length;
      const typed = ln.text.slice(0, Math.round(prog));
      const typing = frame < ln.start + ln.typeDur;
      shown.push({
        idx,
        el: (
          <div style={{ height: LINE_H, display: "flex", alignItems: "center", whiteSpace: "pre" }}>
            <span style={{ color: C.accent, marginRight: 14 }}>$</span>
            <span style={{ color: C.textHi }}>{typed}</span>
            {typing ? <Cursor /> : null}
          </div>
        ),
      });
      return;
    }

    // output line
    const op = interpolate(frame, [ln.start, ln.end], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
    shown.push({
      idx,
      el: (
        <div
          style={{
            height: LINE_H,
            display: "flex",
            alignItems: "center",
            whiteSpace: "pre-wrap",
            color: toneColor(ln.tone),
            opacity: op,
            transform: `translateX(${(1 - op) * 6}px)`,
            fontWeight: ln.tone === "ok" || ln.tone === "err" || ln.tone === "accent" ? 600 : 400,
          }}
        >
          {ln.text}
        </div>
      ),
    });
  });

  // a blinking cursor on the latest line if the active line is an output (waiting)
  const lastActive = timeline.lines[activeIdx];
  const showTrailingCursor =
    activeIdx >= 0 && lastActive && lastActive.kind !== "cmd" && frame >= lastActive.end;

  // auto-scroll: keep the last MAX_LINES visible, counting the trailing cursor line too
  const effective = shown.length + (showTrailingCursor ? 1 : 0);
  const overflow = Math.max(0, effective - MAX_LINES);
  const offset = overflow * LINE_H;

  return (
    <div
      style={{
        width,
        background: "rgba(8,7,5,0.92)",
        border: `1px solid ${C.border}`,
        borderRadius: 16,
        boxShadow: "0 30px 80px rgba(0,0,0,0.55)",
        overflow: "hidden",
        backdropFilter: "blur(2px)",
      }}
    >
      {/* title bar */}
      <div
        style={{
          height: 46,
          display: "flex",
          alignItems: "center",
          gap: 9,
          padding: "0 18px",
          borderBottom: `1px solid ${C.border}`,
          background: C.bg2,
        }}
      >
        <span style={{ width: 13, height: 13, borderRadius: 99, background: "#ff5f56" }} />
        <span style={{ width: 13, height: 13, borderRadius: 99, background: "#ffbd2e" }} />
        <span style={{ width: 13, height: 13, borderRadius: 99, background: "#27c93f" }} />
        <span
          style={{
            marginLeft: 16,
            fontFamily: mono,
            fontSize: 14,
            color: C.textLo,
            letterSpacing: "0.04em",
          }}
        >
          zsh — provenrail
        </span>
      </div>
      {/* body */}
      <div style={{ height: BODY_H, padding: "20px 26px", overflow: "hidden" }}>
        <div
          style={{
            fontFamily: mono,
            fontSize: FONT,
            lineHeight: `${LINE_H}px`,
            transform: `translateY(${-offset}px)`,
          }}
        >
          {shown.map((s) => (
            <div key={s.idx}>{s.el}</div>
          ))}
          {showTrailingCursor ? (
            <div style={{ height: LINE_H, display: "flex", alignItems: "center" }}>
              <span style={{ color: C.accent, marginRight: 14 }}>$</span>
              <Cursor />
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
};
