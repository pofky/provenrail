import { loadFont as loadMono } from "@remotion/google-fonts/DMMono";
import { loadFont as loadSans } from "@remotion/google-fonts/DMSans";

export const mono = loadMono().fontFamily;
export const sans = loadSans().fontFamily;

// Brand palette, matched to provenrail.com (bronze-on-near-black).
export const C = {
  bg: "#0b0a08",
  bg2: "#12100c",
  bg3: "#181510",
  bg4: "#221d15",
  border: "#29221a",
  borderHi: "#3a3124",
  accent: "#d3a957",
  accent2: "#ecca7e",
  accentInk: "#1c1408",
  textHi: "#f3f5f7",
  textMid: "#99a2af",
  textLo: "#5a626e",
  ok: "#7bd88f",
  warn: "#e7b86b",
  err: "#ff7b7b",
  info: "#8aa0b6",
} as const;

export type Tone = "default" | "ok" | "warn" | "err" | "info" | "accent" | "dim";

export const toneColor = (t: Tone | undefined): string => {
  switch (t) {
    case "ok":
      return C.ok;
    case "warn":
      return C.warn;
    case "err":
      return C.err;
    case "info":
      return C.info;
    case "accent":
      return C.accent;
    case "dim":
      return C.textLo;
    default:
      return C.textHi;
  }
};
