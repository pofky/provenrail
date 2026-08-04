import { Tone } from "./theme";

// One line in a terminal transcript.
export type Line =
  | { kind: "cmd"; text: string } // a command you type at the $ prompt
  | { kind: "out"; text: string; tone?: Tone } // program output
  | { kind: "blank" };

// A step groups lines under a caption explaining what is happening.
export type Step = {
  caption: string;
  note?: string;
  lines: Line[];
};

export type TimedLine = Line & {
  start: number; // frame the line first appears
  typeDur: number; // frames spent typing (cmd only; 0 otherwise)
  end: number; // frame the line is fully shown
};

export type TimedStep = {
  caption: string;
  note?: string;
  start: number;
  end: number;
};

export type Timeline = {
  lines: TimedLine[];
  steps: TimedStep[];
  total: number;
};

// Pacing knobs (frames @ 30fps).
const START_PAD = 14;
const CHAR = 1.25; // frames per typed character
const CMD_MIN = 14;
const HOLD_AFTER_CMD = 18;
const OUT_REVEAL = 7;
const OUT_HOLD = 5;
const BLANK = 7;
const STEP_GAP = 16;
const END_PAD = 55;

export const buildTimeline = (steps: Step[]): Timeline => {
  const lines: TimedLine[] = [];
  const tSteps: TimedStep[] = [];
  let cur = START_PAD;

  for (const step of steps) {
    const stepStart = cur;
    for (const line of step.lines) {
      if (line.kind === "cmd") {
        const typeDur = Math.max(CMD_MIN, Math.round(line.text.length * CHAR));
        lines.push({ ...line, start: cur, typeDur, end: cur + typeDur });
        cur += typeDur + HOLD_AFTER_CMD;
      } else if (line.kind === "out") {
        lines.push({ ...line, start: cur, typeDur: 0, end: cur + OUT_REVEAL });
        cur += OUT_REVEAL + OUT_HOLD;
      } else {
        lines.push({ ...line, start: cur, typeDur: 0, end: cur + BLANK });
        cur += BLANK;
      }
    }
    tSteps.push({ caption: step.caption, note: step.note, start: stepStart, end: cur });
    cur += STEP_GAP;
  }

  return { lines, steps: tSteps, total: Math.round(cur + END_PAD) };
};

export const totalFrames = (steps: Step[]): number => buildTimeline(steps).total;
