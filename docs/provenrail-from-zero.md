# Provenrail from zero

The complete beginner walkthrough. From a blank screen to a verified, tamper-evident
record of what your AI agent did. Every keystroke is written out. You do not need to know
how to code, and you do not need to install or understand Python.

This is the written companion to the web page at https://provenrail.com/start. Keep the two
in sync when either changes.

- Time: about 10 minutes
- Works on: macOS, Windows, Linux
- No account, credit card, or prior terminal experience needed
- Nothing leaves your machine in this guide

How to read the commands below: lines starting with `$` are what you type into the terminal
(do not type the `$`). The indented grey lines under a command are roughly what the computer
prints back, so you can check you are on track. Press Enter after each command.

---

## 0. What you need

- A computer running macOS, Windows, or Linux
- An internet connection (only for the two install steps; recording itself works offline)
- About ten minutes

You do not need Python, Node, Docker, an account, or any command-line experience.

---

## 1. Open the terminal

The terminal is a text window where you type a command and press Enter to run it. Open it once
and leave it open for the whole guide.

- macOS: press `Cmd + Space`, type `Terminal`, press Enter.
- Windows: press the Windows key, type `Terminal` (or `PowerShell`), press Enter. If you have
  neither, type `cmd`.
- Linux: press `Ctrl + Alt + T`, or search your apps menu for `Terminal`.

You will see a prompt (a line ending in `%`, `$`, or `>`) with a cursor. That is the computer
waiting for you to type.

Pasting: macOS uses `Cmd + V`; Windows Terminal and most Linux terminals use
`Ctrl + Shift + V` (right-click also works). Paste one command at a time and press Enter.

---

## 2. Install uv (this handles Python for you)

uv is a small, fast tool that installs command-line apps and brings its own copy of Python,
kept separate from everything else on your machine. That isolation is why uv-installed tools do
not break when a system or Homebrew Python is upgraded. Install it once and you never think
about Python again.

macOS / Linux:

```
$ curl -LsSf https://astral.sh/uv/install.sh | sh
```

Windows (PowerShell):

```
> powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Then **close the terminal window completely and open a new one** so your computer can find the
new `uv` command. Confirm it worked:

```
$ uv --version
uv 0.11.6
```

A version number means you are set. `command not found` means see the troubleshooting section.

---

## 3. Install Provenrail

One command. It installs the `pr` tool in its own isolated space, so it cannot clash with
other software.

```
$ uv tool install provenrail
Installed 3 executables: pr, pr-server, pr-verify
```

Check it is there:

```
$ pr
usage: pr [-h] {serve,activate,demo,verify,disclose,report,pack,diff,quickstart,...} ...
```

If `pr` says `command not found`, close and reopen the terminal once, then try again.

---

## 4. Your first proof, with no code at all

Prove the whole idea in two commands. The first creates a sample run sealed into a file (a
"bundle"). The second checks that bundle, recomputing every hash and signature, and reports
whether anything was tampered with.

```
$ pr demo
Recorded a 6-event demo run and sealed it into bundle.json.

Now prove it is tamper-evident. Re-derive every hash and signature, trusting nothing:
  pr verify bundle.json

$ pr verify bundle.json
[info] summary: 6 records, 1 anchors, 0 heartbeats.
RESULT: VERIFIED
The warn/info lines above are advisory context, not failures: the record's integrity is fully proven.
```

That green `VERIFIED` is the entire product in one word: the verifier trusted nobody and
re-derived the record from scratch. To feel the other side, open `bundle.json` in any text
editor, change one character, save, and run `pr verify bundle.json` again. It will report
`TAMPERING DETECTED` and refuse to pass. A changed record cannot pass.

You will also see a few `[warn]` lines before the result, and that is expected on the free
plan. They say things like "local anchor only" and "not witnessed": the record carries your
own machine's time, not a trusted third-party timestamp. That trusted timestamp, plus witness
cosignatures, is the paid Builder feature. The integrity proof is identical on every plan, so
the line that matters is the last one: `RESULT: VERIFIED`. Warnings are guidance, not failures;
only `TAMPERING DETECTED` is a failure.

You can also verify in your browser with no install at all: https://provenrail.com/verify?demo

---

## 5. Record a run of your own agent

A tiny example with no AI keys required, so it runs anywhere.

### 5.1 Make a folder and move into it

`mkdir` makes a folder; `cd` ("change directory") steps into it. Everything after this runs
inside that folder.

```
$ mkdir my-first-agent
$ cd my-first-agent
```

### 5.2 Start the recorder

Starts a small local recorder in the background and writes a config file so your code needs
zero setup. Runs entirely on your own computer.

```
$ pr quickstart
started a local sink (pid 12345) and wrote .provenrail.json

Now your whole setup is two lines:
    import provenrail as fr
    with fr.record('my-agent'):
        ...   # your agent runs; calls are captured automatically
```

### 5.3 Create the script file

In the same folder, make a file named `my_first_agent.py`. In VS Code / Cursor / any editor:
File, New File, paste, save as `my_first_agent.py` inside the `my-first-agent` folder.

```python
import provenrail as fr

with fr.record("my-first-agent") as run:
    run.record_model_call(
        "anthropic", "claude-opus-4-8",
        request={"prompt": "Summarize the contract."},
        response={"text": "Three key risks: A, B, C."},
        usage={"input": "640", "output": "180"},
    )
    run.record_decision("answer is grounded; returning to user", confidence="high")
    run.record_human_oversight("approved", approver="me@example.com")

print("Done. The run was captured and sealed off-box.")
```

No editor open? On macOS or Linux, paste this whole block into the terminal at once:

```
$ cat > my_first_agent.py <<'EOF'
import provenrail as fr
with fr.record("my-first-agent") as run:
    run.record_model_call("anthropic", "claude-opus-4-8",
        request={"prompt": "Summarize the contract."},
        response={"text": "Three key risks: A, B, C."})
    run.record_decision("grounded; returning to user", confidence="high")
print("Done. The run was captured and sealed off-box.")
EOF
```

### 5.4 Run it

`uv run --with provenrail` quietly fetches what the script needs into a throwaway environment,
so you never install or manage Python yourself.

```
$ uv run --with provenrail python my_first_agent.py
Installed 26 packages in 19ms
Done. The run was captured and sealed off-box.
```

That is a real, signed, tamper-evident record of your run. "Off-box" means it is written
somewhere your agent code cannot quietly rewrite, which is the point of an independent record.

### 5.5 Verify your own run, free and offline

`pr export` pulls your sealed run out of the recorder into a bundle; `pr verify` recomputes every
hash and signature and confirms it is intact, trusting nobody.

```
$ pr export my-run.json
wrote my-run.json (4 records, 1 anchors). Verify it yourself with:
    pr verify my-run.json

$ pr verify my-run.json
RESULT: VERIFIED
```

That is the whole promise on your own machine for free: a record of what your agent did that you
can prove was not altered after the fact. Tamper with one character of `my-run.json` and
re-verify to watch it fail.

### 5.6 Turn it into something you can hand over (this is the point)

A green VERIFIED is the proof. The value is what you do with it. Two commands turn your run into a
deliverable, both free and on your own machine.

A readable report for a client or auditor:

```
$ pr report --regime eu-ai-act my-run.json --md > report.md
```

That writes a plain-English `report.md`: what was recorded, whether integrity verified, an events
breakdown, and how they map to EU AI Act Article 12. Swap in `--regime hipaa` or `--regime generic`
for other contexts. On this free local setup the report honestly notes that recorded times are
self-asserted; the Builder plan adds RFC 3161 trusted time so an auditor can rely on the timing too.

A self-contained evidence package for an auditor:

```
$ pr pack my-run.json --out evidence.zip
Wrote 12893 byte evidence pack to evidence.zip (regime=generic)   # exact size varies by run
Contents: bundle.json, attestation, VERIFY.txt, MANIFEST.json
```

Hand over `evidence.zip`. It carries the run, a written attestation, and a `VERIFY.txt` that tells
the recipient exactly how to check it themselves with the open-source verifier, trusting nothing you
say. You do not ask them to trust you; you hand them proof they can verify.

### 5.6a What the record stores: a fingerprint, not your text (by default)

By default Provenrail stores a SHA-256 **fingerprint** of each prompt and response, not the text
itself, so your prompts and outputs never leave your machine inside the record. The integrity proof
still covers the full sequence, order, and timing of events.

That fingerprint is how you prove a transcript later. Keep your own copy of what the agent said, and
anyone can confirm it is the real, unaltered version:

```
$ echo '{"text":"Three key risks: A, B, C."}' > response.json
$ pr verify-content my-run.json --file response.json
MATCH: this content is recorded in the bundle (sha256 2df9a8a4...).
  seq 1 model_call.response
```

A `MATCH` proves that exact content was what the record committed to; change one character and it
reports `NO MATCH`. If you would rather store the text directly inside the record (no separate
transcript to keep), record with `capture_content=True`:

```python
with fr.record("my-agent", capture_content=True):
    ...
```

### 5.7 Stop the recorder when done

```
$ pr quickstart --stop
stopped the local Provenrail sink
```

---

## 6. Capture your real AI calls automatically

In a real app you do not log events by hand. Hand Provenrail your OpenAI or Anthropic client
once, and every model call inside the recorded block is captured:

```python
import provenrail as fr
from openai import OpenAI

client = OpenAI()

with fr.record("billing-agent", clients=[client]):
    client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "..."}],
    )
    # every call your agent makes in here is recorded, no extra lines
```

Anthropic works the same way (pass your Anthropic client in `clients=[...]`). LangChain and MCP
are supported too; anything else records with one explicit line. Full reference: /docs.

---

## 7. Share a proof and go live

Everything above runs free on your own machine. To let a teammate, client, or auditor verify a
run without installing anything, Provenrail can host the record behind a shareable proof link
and add a trusted timestamp from an independent authority. That is the paid tier.

1. Go to https://provenrail.com/account and sign in with your email (one-click magic link).
2. Pick a plan. After payment your account page shows a license key starting with `prl_live_`.
3. Activate it:

```
$ pr activate prl_live_your_key_here
License valid: builder tier (no expiry). Verified offline, nothing was sent anywhere.
```

The key is checked on your own machine, offline. Your runs can then carry trusted timestamps
and shareable proof links. See /#pricing for what each tier includes.

---

## If something goes wrong

| What you see | What to do |
| --- | --- |
| `command not found: uv` or `pr` | Close the terminal window completely and open a new one, then retry. Fixes it almost every time. |
| `command not found: python` / `python3` | You do not need a system Python. Use `uv run --with provenrail python ...` exactly as written. |
| Installed Python with Homebrew and tools broke | Use `uv tool install provenrail`, not `pip`. uv keeps its own Python, so a `brew upgrade` cannot orphan it. |
| `permission denied` during install | Do not add `sudo`. These commands install into your own user space and never need admin rights. |
| `pr verify` says `TAMPERING DETECTED` | If you edited the bundle on purpose, that is correct. Otherwise re-run `pr demo` for a fresh bundle and verify that. |
| `pr verify` says `NOT CONFIRMED` | The record is intact, but a key you passed with `--tlog-pubkey` or `--witness-pubkeys` does not match. The usual cause is reusing keys from an earlier `pr demo` run; each run prints fresh keys, so copy them from the same run's output. This is not tampering. |
| `pr verify` says `NOT A PROVENRAIL BUNDLE` | The file is valid JSON but not a bundle. Check you pointed `pr verify` at the right file, one made by `pr demo` or `pr export`. |
| `pr verify` says `that file is not valid JSON` | You likely broke the file structure while editing. Re-export it, or run `pr demo` for a fresh bundle. |
| The `cat > ... EOF` block hangs | That shortcut is macOS/Linux only. On Windows, create the file in Notepad or VS Code instead. |
| Nothing happens after I paste | You probably did not press Enter. Paste one command at a time, then Enter. |

Still stuck? Email support@provenrail.com with the exact command and the exact message.

---

## FAQ

**Do I need to know how to code?** No. Steps 1 to 4 are pure copy and paste and give a real
verified proof. Recording your own agent means pasting one short file you do not need to
understand.

**Do I need Python installed?** No. uv brings its own Python, and `uv run` uses it.

**Does the folder matter?** Not for installing. For recording your own run, make a folder and
`cd` into it first, so the config file and your script live together.

**Do I keep the terminal open?** Keep it open while you work through the guide. The local
recorder runs until you `pr quickstart --stop` or close the terminal. Installed tools stay
installed.

**Is my data sent to Provenrail?** Not in this guide. Install, record, and verify all happen
locally and work offline. Data only leaves your machine if you later choose a hosted plan.

**Windows?** Yes. Use the Windows lines for the terminal and the uv install; everything else is
identical.
