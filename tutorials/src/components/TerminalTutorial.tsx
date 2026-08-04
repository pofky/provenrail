import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { C, mono, sans } from "../theme";
import { buildTimeline, Step } from "../lib";
import { Terminal } from "./Terminal";
import { Frame } from "./Frame";

export const TerminalTutorial: React.FC<{
  eyebrow: string;
  title: string;
  steps: Step[];
}> = ({ eyebrow, title, steps }) => {
  const frame = useCurrentFrame();
  const tl = buildTimeline(steps);

  // current step for the caption track
  let active = 0;
  tl.steps.forEach((s, i) => {
    if (frame >= s.start) active = i;
  });
  const step = tl.steps[active];
  const stepLocal = frame - step.start;
  const capIn = interpolate(stepLocal, [0, 12], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  return (
    <Frame eyebrow={eyebrow} title={title}>
      {/* terminal, centered, with room for the caption panel below */}
      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", paddingTop: 70 }}>
        <Terminal timeline={tl} />
      </AbsoluteFill>

      {/* step caption panel, bottom-left */}
      <div
        style={{
          position: "absolute",
          left: 64,
          bottom: 52,
          maxWidth: 760,
          display: "flex",
          alignItems: "flex-start",
          gap: 16,
          opacity: capIn,
          transform: `translateY(${(1 - capIn) * 10}px)`,
        }}
      >
        <div
          style={{
            fontFamily: mono,
            fontSize: 15,
            fontWeight: 500,
            color: C.accentInk,
            background: C.accent,
            borderRadius: 8,
            padding: "6px 12px",
            whiteSpace: "nowrap",
          }}
        >
          STEP {active + 1}/{tl.steps.length}
        </div>
        <div>
          <div style={{ fontSize: 27, fontWeight: 700, color: C.textHi, lineHeight: 1.25 }}>
            {step.caption}
          </div>
          {step.note ? (
            <div style={{ fontSize: 19, color: C.textMid, marginTop: 6, lineHeight: 1.4, fontFamily: sans }}>
              {step.note}
            </div>
          ) : null}
        </div>
      </div>
    </Frame>
  );
};
