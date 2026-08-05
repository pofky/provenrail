# Provenrail tutorial videos (Remotion)

Motion-graphic, step-by-step tutorials for the landing page / docs / social. Every command and
program output shown is **verbatim real output** captured from `provenrail 0.2.29` (not mocked).

## Compositions

| id | file | what it covers | ~length |
|----|------|----------------|---------|
| `GettingStarted` | `src/data/gettingStarted.ts` | install -> `pr quickstart` -> `pr demo` -> `pr verify` | 16s |
| `VerifyYourself` | `src/data/verifyYourself.ts` | witnessed verify + live tamper detection + CI exit code | 20s |
| `PlansLicensing` | `src/compositions/PlansLicensing.tsx` | sign in -> subscribe (Builder) -> license key -> `pr activate` | 25s |
| `RecordEvidence` | `src/data/recordEvidence.ts` | Python + TypeScript `record()` -> `pr report` -> `pr pack` | 22s |
| `TeamSso` | `src/data/teamSso.ts` | invite members + roles -> configure OIDC SSO -> IdP login (JIT) | 31s |

## Preview

```bash
npm install
npm start          # Remotion Studio at http://localhost:3000
```

## Render (1920x1080, H.264)

```bash
npx remotion render src/index.ts GettingStarted out/01-getting-started.mp4 --codec h264 --crf 20
npx remotion render src/index.ts VerifyYourself out/02-verify-yourself.mp4 --codec h264 --crf 20
npx remotion render src/index.ts PlansLicensing out/03-plans-licensing.mp4 --codec h264 --crf 20
npx remotion render src/index.ts RecordEvidence out/04-record-evidence.mp4 --codec h264 --crf 20
npx remotion render src/index.ts TeamSso out/05-team-sso.mp4 --codec h264 --crf 20
```

For a 9:16 social cut, add `--width 1080 --height 1920` (layout is centered, so it reflows).

## Editing content

The three terminal tutorials are pure data: edit the `steps` array in the matching `src/data/*.ts`
file. Each line is `{kind:"cmd"|"out"|"blank", text, tone?}`. Timing is derived automatically in
`src/lib.ts` (typing speed, holds, step gaps), no manual frame math.

Brand palette and fonts: `src/theme.ts`. Terminal engine: `src/components/Terminal.tsx`.

> License: Remotion is free for individuals and orgs of <=3. These are our own assets. Do not commit
> rendered mp4s; regenerate with the commands above.
