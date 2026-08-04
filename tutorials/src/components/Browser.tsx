import React from "react";
import { C, mono, sans } from "../theme";

export const Browser: React.FC<{ url: string; children: React.ReactNode; width?: number; height?: number }> = ({
  url,
  children,
  width = 1180,
  height = 600,
}) => (
  <div
    style={{
      width,
      background: C.bg2,
      border: `1px solid ${C.border}`,
      borderRadius: 16,
      boxShadow: "0 30px 80px rgba(0,0,0,0.55)",
      overflow: "hidden",
    }}
  >
    <div
      style={{
        height: 50,
        display: "flex",
        alignItems: "center",
        gap: 9,
        padding: "0 18px",
        borderBottom: `1px solid ${C.border}`,
        background: C.bg3,
      }}
    >
      <span style={{ width: 13, height: 13, borderRadius: 99, background: "#ff5f56" }} />
      <span style={{ width: 13, height: 13, borderRadius: 99, background: "#ffbd2e" }} />
      <span style={{ width: 13, height: 13, borderRadius: 99, background: "#27c93f" }} />
      <div
        style={{
          marginLeft: 18,
          flex: 1,
          height: 30,
          borderRadius: 8,
          background: C.bg,
          border: `1px solid ${C.border}`,
          display: "flex",
          alignItems: "center",
          padding: "0 14px",
          fontFamily: mono,
          fontSize: 15,
          color: C.textMid,
        }}
      >
        <span style={{ color: C.ok, marginRight: 8, fontSize: 12 }}>🔒</span>
        {url}
      </div>
    </div>
    <div style={{ height, background: C.bg, fontFamily: sans, position: "relative" }}>{children}</div>
  </div>
);

// Reusable card + button atoms matching the real account page.
export const Card: React.FC<{ children: React.ReactNode; style?: React.CSSProperties }> = ({ children, style }) => (
  <div
    style={{
      background: C.bg2,
      border: `1px solid ${C.border}`,
      borderRadius: 16,
      padding: 24,
      ...style,
    }}
  >
    {children}
  </div>
);

export const OAuthBtn: React.FC<{ label: string; icon: React.ReactNode }> = ({ label, icon }) => (
  <div
    style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      gap: 12,
      height: 56,
      borderRadius: 12,
      background: C.bg3,
      border: `1px solid ${C.border}`,
      color: C.textHi,
      fontSize: 19,
      fontWeight: 600,
    }}
  >
    {icon}
    {label}
  </div>
);

export const Pill: React.FC<{ text: string; on?: boolean }> = ({ text, on }) => (
  <span
    style={{
      fontFamily: mono,
      fontSize: 16,
      padding: "5px 14px",
      borderRadius: 999,
      background: on ? "rgba(211,169,87,0.14)" : C.bg3,
      color: on ? C.accent : C.textMid,
      border: `1px solid ${on ? "rgba(211,169,87,0.4)" : C.border}`,
      textTransform: "capitalize",
    }}
  >
    {text}
  </span>
);
