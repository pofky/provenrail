// Type definitions for the Provenrail TypeScript / Node SDK.

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export interface Usage {
  input?: string | number;
  output?: string | number;
  [k: string]: unknown;
}

/** A signed agent activity record (the shape sent to the sink and verified offline). */
export interface Record {
  v: string;
  stream_id: string;
  session_id: string;
  record_id: string;
  seq: number;
  prev_hash: string;
  ts_utc: string;
  pubkey: string;
  action_type: string;
  payload: Record_Payload;
  record_hash: string;
  record_sig: string;
}
type Record_Payload = { [k: string]: Json };

export type Transport = (records: Record[]) => Promise<unknown>;

export interface RecorderOptions {
  endpoint?: string;
  writeToken?: string;
  streamId?: string;
  /** Inject a transport (tests, custom delivery). Default posts to the sink's /v1/ingest. */
  transport?: Transport;
  /** Store cleartext content alongside the hash. Default false (hash-not-content, PII-safe). */
  captureContent?: boolean;
}

export interface SessionOptions extends RecorderOptions {
  accountKey?: string;
  meta?: Record_Payload;
}

export class SigningKey {
  static generate(): Promise<SigningKey>;
  publicKeyHex(): string;
  sign(bytes: Uint8Array): Promise<string>;
}

export class Recorder {
  readonly streamId: string;
  readonly records: Record[];
  static create(opts: RecorderOptions): Promise<Recorder>;
  start(meta?: Record_Payload): Promise<Record>;
  seal(outcome?: string, trigger?: string): Promise<Record>;
  session<T>(meta: Record_Payload, fn: (pr: Recorder) => Promise<T>): Promise<T>;
  record(actionType: string, payload: Record_Payload): Promise<Record>;
  recordModelCall(
    provider: string, model: string, request: Json, response: Json,
    opts?: { usage?: Usage } & Record_Payload,
  ): Promise<Record>;
  recordToolCall(
    name: string, args: Json, result: Json,
    opts?: { outcome?: string; kind?: string } & Record_Payload,
  ): Promise<Record>;
  recordMcpCall(name: string, args: Json, result: Json, opts?: Record_Payload): Promise<Record>;
  recordDecision(summary: string, fields?: Record_Payload): Promise<Record>;
  recordDataAccess(resource: string, op: string, fields?: Record_Payload): Promise<Record>;
  recordHumanOversight(action: string, fields?: Record_Payload): Promise<Record>;
  heartbeat(): Promise<Record>;
}

export function configure(opts: Partial<SessionOptions>): void;
export function makeRecorder(agent: string, opts?: SessionOptions): Promise<Recorder>;
export function record<T>(
  agent: string, fn: (pr: Recorder) => Promise<T>, opts?: SessionOptions,
): Promise<T>;
export function provisionStream(
  endpoint: string, opts?: { label?: string; accountKey?: string },
): Promise<{ stream_id: string; write_token: string; read_token: string; [k: string]: unknown }>;

export function instrumentOpenAI<T>(client: T, recorder: Recorder): T;
export function instrumentAnthropic<T>(client: T, recorder: Recorder): T;

export function canon(value: Json): string;
export function hashValue(value: Json): Promise<string>;
export class CanonicalError extends Error {}
