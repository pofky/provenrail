-- The anchor-only trust service.
--
-- Two tables, and what is absent from them is the design. There is no column here that could
-- hold a prompt, a completion, a tool call, or any part of a customer's agent records, because
-- the service never receives one. The operator trades as a Lithuanian sole proprietorship with
-- no liability shield, and holding customer agent records would make him a GDPR processor
-- personally. A SHA-256 Merkle root over record hashes is not personal data by any route: not
-- identifiable, not reversible, not linkable to a person without data that is never held here.
--
-- Applied to the production project. Additive only: it creates new tables and touches nothing
-- that already exists.

create table if not exists public.anchor_accounts (
    account_id   text primary key,
    api_key_hash text not null unique,   -- sha256 of the key; the key itself is never stored
    label        text,
    active       boolean not null default true,
    created_at   timestamptz not null default now()
);

create table if not exists public.external_anchors (
    anchor_id    text primary key,
    account_id   text not null references public.anchor_accounts(account_id),
    stream_id    text not null,          -- the customer's own label, opaque to us
    merkle_root  text not null,          -- 64 hex chars, over THEIR record hashes
    covers_up_to bigint not null check (covers_up_to >= 1),
    receipt      jsonb not null,         -- the signed AnchorReceipt
    created_at   timestamptz not null default now()
);

-- Makes the "furthest anchor for this stream" lookup an index seek rather than a scan, and,
-- more importantly, makes a race lose at the database rather than at the application. Two
-- concurrent requests can both pass the coverage pre-check; only one can hold this row.
create unique index if not exists external_anchors_one_per_length
    on public.external_anchors(account_id, stream_id, covers_up_to);

-- Nothing reaches these tables except the edge function, which uses the service role. Enabling
-- RLS with no permissive policy is the whole access rule: anon and authenticated get nothing,
-- including the public read, which is served by the function rather than by PostgREST so that
-- the account_id is never in a response.
alter table public.anchor_accounts  enable row level security;
alter table public.external_anchors enable row level security;

comment on table public.external_anchors is
  'Merkle roots published by customers who self-host their own sink. Contains no customer '
  'records and no personal data by construction. Coverage per (account, stream) may only grow: '
  'enforced by the edge function and by external_anchors_one_per_length.';
