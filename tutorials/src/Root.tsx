import "./index.css";
import { Composition } from "remotion";
import { TerminalTutorial } from "./components/TerminalTutorial";
import { PlansLicensing, PLANS_DURATION } from "./compositions/PlansLicensing";
import { totalFrames } from "./lib";
import * as GettingStarted from "./data/gettingStarted";
import * as VerifyYourself from "./data/verifyYourself";
import * as RecordEvidence from "./data/recordEvidence";
import * as TeamSso from "./data/teamSso";
import * as GuardAgent from "./data/guardAgent";

const W = 1920;
const H = 1080;
const FPS = 30;

export const RemotionRoot: React.FC = () => {
  return (
    <>
      <Composition
        id="GettingStarted"
        component={TerminalTutorial}
        durationInFrames={totalFrames(GettingStarted.steps)}
        fps={FPS}
        width={W}
        height={H}
        defaultProps={{
          eyebrow: GettingStarted.eyebrow,
          title: GettingStarted.title,
          steps: GettingStarted.steps,
        }}
      />
      <Composition
        id="VerifyYourself"
        component={TerminalTutorial}
        durationInFrames={totalFrames(VerifyYourself.steps)}
        fps={FPS}
        width={W}
        height={H}
        defaultProps={{
          eyebrow: VerifyYourself.eyebrow,
          title: VerifyYourself.title,
          steps: VerifyYourself.steps,
        }}
      />
      <Composition
        id="PlansLicensing"
        component={PlansLicensing}
        durationInFrames={PLANS_DURATION}
        fps={FPS}
        width={W}
        height={H}
      />
      <Composition
        id="RecordEvidence"
        component={TerminalTutorial}
        durationInFrames={totalFrames(RecordEvidence.steps)}
        fps={FPS}
        width={W}
        height={H}
        defaultProps={{
          eyebrow: RecordEvidence.eyebrow,
          title: RecordEvidence.title,
          steps: RecordEvidence.steps,
        }}
      />
      <Composition
        id="TeamSso"
        component={TerminalTutorial}
        durationInFrames={totalFrames(TeamSso.steps)}
        fps={FPS}
        width={W}
        height={H}
        defaultProps={{
          eyebrow: TeamSso.eyebrow,
          title: TeamSso.title,
          steps: TeamSso.steps,
        }}
      />
      <Composition
        id="GuardAgent"
        component={TerminalTutorial}
        durationInFrames={totalFrames(GuardAgent.steps)}
        fps={FPS}
        width={W}
        height={H}
        defaultProps={{
          eyebrow: GuardAgent.eyebrow,
          title: GuardAgent.title,
          steps: GuardAgent.steps,
        }}
      />
    </>
  );
};
