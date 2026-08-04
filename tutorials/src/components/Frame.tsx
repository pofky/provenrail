import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { C, mono, sans } from "../theme";

// Brand logo mark: a simple bronze ring + check, drawn in SVG so no asset is needed.
const Mark: React.FC<{ size?: number }> = ({ size = 34 }) => (
  <svg width={size} height={size} viewBox="0 0 32 32" fill="none">
    <circle cx="16" cy="16" r="13" stroke={C.accent} strokeWidth="2" />
    <path
      d="M10 16.5l4 4 8-9"
      stroke={C.accent}
      strokeWidth="2.6"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export const Frame: React.FC<{
  title: string;
  eyebrow: string;
  children: React.ReactNode;
}> = ({ title, eyebrow, children }) => {
  const frame = useCurrentFrame();
  const enter = interpolate(frame, [0, 18], [0, 1], { extrapolateRight: "clamp" });
  return (
    <AbsoluteFill style={{ background: C.bg, fontFamily: sans }}>
      {/* soft accent glow top-left */}
      <div
        style={{
          position: "absolute",
          top: -260,
          left: -180,
          width: 720,
          height: 720,
          background: `radial-gradient(circle, rgba(211,169,87,0.10), transparent 62%)`,
          filter: "blur(8px)",
        }}
      />
      {/* header */}
      <div
        style={{
          position: "absolute",
          top: 44,
          left: 64,
          right: 64,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          opacity: enter,
          transform: `translateY(${(1 - enter) * -12}px)`,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <Mark />
          <span
            style={{
              fontFamily: mono,
              fontSize: 26,
              fontWeight: 500,
              color: C.textHi,
              letterSpacing: "-0.01em",
            }}
          >
            proven<span style={{ color: C.accent }}>rail</span>
          </span>
        </div>
        <div style={{ textAlign: "right" }}>
          <div
            style={{
              fontFamily: mono,
              fontSize: 14,
              letterSpacing: "0.22em",
              textTransform: "uppercase",
              color: C.accent,
            }}
          >
            {eyebrow}
          </div>
          <div style={{ fontSize: 26, fontWeight: 700, color: C.textHi, marginTop: 4 }}>
            {title}
          </div>
        </div>
      </div>
      {children}
    </AbsoluteFill>
  );
};
