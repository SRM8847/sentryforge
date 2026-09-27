# SentryForge (Wazuh Edition)

A hands-on detection engineering lab. It's built on two Ubuntu 24.04 virtual machines:

- **ubuntu-wazuh** — runs the Wazuh manager, indexer, and dashboard (the "brain" that receives, decodes, and alerts on security events)
- **monitored** — a regular Ubuntu machine being watched, running the Wazuh agent and Linux's `auditd` audit daemon

The core idea: instead of hand-writing detection rules directly in Wazuh's native (and fairly verbose) XML format, rules are written as simple, constrained YAML files in the [Sigma](https://github.com/SigmaHQ/sigma) style — a widely-used, human-readable format for describing "what does this attack look like in the logs." A custom Python script then converts those YAML rules into real Wazuh XML rules, which get tested against real captured attack data before being deployed.

This document explains what was actually built, phase by phase, and — more importantly — *why* each decision was made, including the mistakes made along the way and how they were fixed. (Phases 1 and 2 — environment setup and the base Wazuh installation — are covered in `docs/explanation.md`; this README picks up from Phase 3 onward, where the real detection engineering work begins.)

---

## Phase 3 — Getting real security data flowing

**The problem this phase solves:** A SIEM (Wazuh) is useless without data to analyze. Before writing any detection logic, we needed the monitored machine to actually generate rich security telemetry and reliably ship it to the manager.

**What we did:**
- Installed the **Wazuh agent** on the monitored machine and confirmed it registered and stayed connected to the manager.
- Installed **auditd**, the Linux kernel's built-in audit subsystem, which can watch things like "who ran this program," "who read this file," "who opened this network connection" — far more granular than normal system logs.
- Loaded a well-regarded community rule set (the **Neo23x0 ruleset**) to tell auditd *what* to watch. Out of the box, this ruleset threw a bunch of load errors — some rules assumed 32-bit CPU support this machine doesn't have, some assumed SELinux (this machine uses AppArmor instead), and some watched for tools (like CrowdStrike or Filebeat) that simply aren't installed here. Each of these was diagnosed individually and the irrelevant rules were removed, leaving a clean, fully-loading rule set tailored to this actual machine.
- Discovered that just running auditd locally isn't enough — Wazuh doesn't automatically ship every log file to the manager. We had to explicitly tell it to watch `/var/log/audit/audit.log` by adding a config block for it.
- Proved the whole pipeline worked end-to-end using a tool called `wazuh-logtest`, which lets you feed in a raw log line and see exactly how Wazuh decodes it and which rule (if any) it matches — without needing to wait for a real event.

**Why it matters:** Every later phase depends on this pipeline being solid. If auditd isn't watching the right things, or the agent isn't shipping the right file, no amount of clever rule-writing later would ever see any data to work with.

---

## Phase 4 — Writing our first real detection, by hand

**The problem this phase solves:** Prove the whole idea — Sigma YAML → converter → Wazuh XML → real alert — actually works, on one simple, well-understood case, before scaling up.

**The detection:** *"Someone used `sudo` to open a `/bin/bash` shell directly"* — a classic way attackers (or careless admins) escalate from a normal user to a root shell. This maps to MITRE ATT&CK technique **T1548.003**.

**What we did:**
- Wrote the rule as a small YAML file, deliberately restricted to simple **AND-only** logic (e.g. "this field equals sudo AND this field equals /bin/bash") — no OR conditions. This isn't a limitation we stumbled into; it's a deliberate design choice, because Wazuh's own rule engine has no clean native way to express "this OR that" inside a single rule. Rather than fake OR support with fragile workarounds, the converter simply refuses anything that isn't a flat AND — an honest boundary, clearly documented.
- Built the actual **converter script** (`sigma_to_wazuh.py`) — a Python program that reads these YAML rules and writes out real Wazuh XML rules, automatically assigning each one a unique ID from Wazuh's reserved "custom rule" ID range.
- **Hit a real bug immediately**: the rule simply didn't fire. Investigating with `wazuh-logtest` revealed that Wazuh's own built-in rules for `sudo` are structured as a small family tree — one base rule, with several more specific "child" rules layered on top of it. Our rule had been written to compete directly with that base rule instead of joining the family as a child — so Wazuh's built-in rule always won. The fix: restructure our rule to be a proper child of the same base rule, and teach the converter to support this "parent rule" relationship.
- Deployed the fixed rule for real using Wazuh's REST API (not just by manually copying a file), and confirmed — by actually running `sudo bash` on the monitored machine multiple times — that the custom rule fired correctly, live, end to end.

**Why it matters:** This phase is where the project stopped being theoretical. It proved the entire pipeline works, and more importantly, it surfaced a real, non-obvious lesson about how Wazuh's rule engine actually behaves — a lesson that saved a lot of time in every phase that followed.

---

## Phase 5 — Capturing real attack evidence (fixtures)

**The problem this phase solves:** To trust that a detection rule actually works — and to prove it doesn't fire on harmless activity — you need real examples of both. This phase captured that evidence for four attack techniques, so future rules (and future automated testing) have something real to check against.

**The four techniques covered:**
1. **T1548.003** — sudo → bash (reused from Phase 4)
2. **T1110** — SSH brute-force login attempts
3. **T1059.004** — a reverse shell (a classic way attackers get remote control of a machine)
4. **T1053.003** — planting a malicious scheduled task via `cron`

**What we did, and what went wrong along the way:**
- Initially, log evidence was gathered by running a command, looking at its output, and **manually retyping it** into a file. This was flagged as a bad habit — not because it's wrong data, but because it's not *reproducible*. A real engineering pipeline should be able to regenerate this evidence with a script, not a human copying text by hand.
- The fix: realized the exact same data is already sitting on the Wazuh manager itself, because the agent had already shipped it there. So instead of typing anything by hand — or even copying files between the two machines — every fixture was extracted with a single `grep` command run directly against the manager's own log files.
- For the SSH brute-force fixture, used a tool called **Hydra** to simulate a real (but harmless, local-only) password-guessing attack against a disposable test account, then cleaned that account up afterward.
- For the reverse shell fixture, triggered a real reverse shell locally (connecting back to a listener on the same machine — nothing exposed to the outside world) and captured the exact sequence of low-level system calls it produced.
- Along the way, hit and fixed a genuine infrastructure problem: re-enabling full log archiving and restarting the Wazuh manager caused it to hang and fail, because old processes hadn't fully shut down before new ones tried to start. Fixed by using Wazuh's own control script for a clean stop/start instead of the generic system service manager.
- Also learned two subtle technical lessons: Linux's audit system can **reuse** session ID numbers over time (so filtering on one isn't always safe), and that a command like `echo` doesn't generate the same kind of trackable event as an external program like `cat` does, because `echo` runs inside the existing shell process rather than starting a new one.
- For the cron fixture, added (and then promptly removed) a fake malicious-looking scheduled task, and a separate harmless one, to capture both sides.

**Why it matters:** Every one of the "gotchas" hit in this phase — recycled session IDs, builtin vs. external commands, a hung service restart — are the kind of thing you only learn by actually doing the work, not by reading documentation. They're now documented so they never cost time again.

---

## Phase 6 — Writing the rest of the detections (and being honest about limits)

**The problem this phase solves:** Turn three of the four Phase 5 techniques into real, tested, deployed detection rules — and make a defensible, evidence-based call about the fourth, rather than forcing a rule that wouldn't really work.

**Detection: T1059.004 (reverse shell)**
- The signal chosen: a `bash` process directly opening a network connection — something normal programs essentially never do on their own. This required extending the converter slightly, because auditd's decoded fields (like `audit.exe`) keep a naming style the converter didn't originally support.
- Carefully tested that the rule requires *both* "the program is bash" *and* "it's making a network connection" — not just the first condition alone, since plain bash usage is extremely common and checking only that would have caused constant false alarms.

**Investigated but not implemented: T1053.003 (cron persistence)**
- The original goal was a smarter version of "someone changed root's scheduled tasks" — specifically, one that could tell if the new scheduled task looked suspicious (e.g., contained a command that downloads and runs something). Investigation showed this isn't actually possible from the data available: the system log for a cron change only records *that* a change happened, never *what* changed.
- A promising alternative — Wazuh's File Integrity Monitoring feature, which can capture the literal contents of a changed file — was tested and found to have a structural limitation: the `crontab` tool doesn't edit its file in place, it replaces it entirely, which this feature doesn't handle the same way as a normal edit.
- **Decision:** rather than write a "custom" rule that would only duplicate what Wazuh's own built-in cron-change alert already does, this was documented as a deliberate non-implementation, backed by direct testing rather than assumption. In real detection engineering work, correctly recognizing "this isn't achievable with the data we have" is just as valuable as writing a rule that works.

**Detection: T1110 (SSH brute force)**
- This detection is fundamentally different from the others: a single log line can never represent "many failed attempts in a row." Wazuh has a native way to express this — count how many times a rule fires within a time window — which required extending the converter again to support this "frequency" pattern.
- Discovered that Wazuh already ships a built-in brute-force detector, but testing against our own captured evidence proved it has a real gap: it's tuned to catch a slow, large-scale attack (8 failures over 3 minutes), and would likely miss a fast, small burst like the one we simulated. The custom rule fills that specific gap with a much faster, tighter threshold, proven against real captured data before being deployed live.

**Why it matters:** This phase is where the project moved from "does the idea work" (Phase 4) to genuine detection engineering judgment — knowing when a custom rule adds real value, when it would just duplicate existing coverage, and when the underlying data simply doesn't support what you'd like to detect.

---

## Phase 7 — Turning this into a real, versioned project

**The problem this phase solves:** Everything up to this point lived only as files in a folder on one machine. To actually automate anything — or let anyone else see, review, or build on this work — it needed to become a real Git repository with a home on GitHub, plus a way for automation to actually run commands on the machine.

**What we did:**
- Organized the working folder into a clean structure — rules, the converter, the captured evidence, and documentation each in their own folder — and set up Git to deliberately **not** track the converter's generated output file, since that's something automation should always regenerate fresh rather than trust a possibly-stale committed copy of.
- Pushed the whole thing to a real GitHub repository.
- Installed something called a **self-hosted runner** directly on the Wazuh manager machine. Normally, GitHub runs your automation on its own temporary cloud computers — but our automation needs to use tools (`wazuh-logtest`, the live Wazuh API) that only exist on this specific machine, so GitHub's own computers could never do this work. A self-hosted runner is simply GitHub's automation software installed to run locally on our own machine instead, listening for jobs to do.

**Why it matters:** This phase has no clever logic in it, but it's the bridge that makes real automation possible at all. Skipping straight to writing automation without this piece would mean having nowhere for that automation to actually execute.

---

## Phase 8 — Making it fully automatic

**The problem this phase solves:** Up to now, every single step — converting a rule, testing it, deploying it — required a person typing commands correctly, in the right order, on the right machine. This phase's entire goal was to make that happen automatically: push a change to GitHub, and have the system convert it, test it against real evidence, and deploy it live — with zero manual steps, and with a real safety net that stops a bad rule before it ever reaches production.

**What we did:**
- Built an automated test script that feeds each of our captured fixtures into `wazuh-logtest` and checks whether the expected rule fired (or, for benign fixtures, correctly *didn't* fire) — turning what had been a manual "type this in and eyeball the output" process into something a computer can check and report pass/fail on by itself.
- Built a deploy script that authenticates to Wazuh, uploads the newly-converted rules, and restarts the manager — but only ever runs if every single test passed first.
- Wrote the actual GitHub Actions automation file that ties it all together: whenever rule files change and get pushed, automatically run convert → test → deploy, in that order, stopping immediately if any step fails.

**What went wrong, and what it taught us (this is the most valuable part of this phase):**
- The very first automated run failed almost immediately, because our tool for feeding data into Wazuh's test system writes its results in a place our script wasn't looking — a mismatch that had been completely invisible during months of manual testing, only surfacing the moment a computer (rather than a human eye) tried to read the output precisely.
- Right after fixing that, a *second*, unrelated bug in the same test script was uncovered — a small pattern-matching mistake that had been silently failing to find anything the whole time, hidden underneath the first bug.
- Getting the automation to actually run on the server surfaced a genuinely important lesson: things that work perfectly when a person is sitting at the keyboard typing commands can fail in completely unexpected ways when a computer runs the exact same commands with nobody watching — specifically, needing a password when nobody's there to type one, and a script quietly relying on a shortcut that only worked because of a leftover unlock from a few minutes earlier.
- The very last failure was the automation being too impatient — checking whether the system had finished restarting after a fixed, arbitrary wait, when we already knew from earlier work that a restart can sometimes take longer. Fixed by having it patiently check back every few seconds instead of guessing a single wait time, and by having it double check the actual result was correct — not just that the service was technically running.
- After fixing all of this, one final real-world test confirmed it end-to-end: a rule was pushed, the automation picked it up, tested it, deployed it — completely unattended — and then, moments later, deliberately triggering the real attack behavior on the monitored machine produced a live alert, proving the whole automated chain actually works, not just that it reports success.

**Why it matters:** This is genuinely the difference between "I know the correct manual steps" and "I built a working system." Every single problem hit in this phase only exists because a computer, not a person, was now doing the work — and each one is a small but real lesson about the gap between doing something by hand and building something that runs itself reliably.

---

## Current state

- **3 working, live, tested custom detections**: T1548.003, T1059.004, T1110.
- **1 technique (T1053.003) deliberately left to Wazuh's built-in coverage**, with the reasoning documented rather than assumed.
- A converter that supports three distinct kinds of rules — simple field matches, matches on differently-named decoder fields, and time-window frequency correlation — each added only when a real, tested need justified it, not speculatively.
- 8 real, reproducibly-captured log fixtures covering both malicious and benign activity for every technique investigated.
- **A fully automated pipeline**: push a rule change to GitHub, and it gets converted, tested against real evidence, and deployed live with no manual steps — confirmed working end-to-end against real attack behavior on the monitored machine.

See `docs/explanation.md` for the full phase-by-phase build log, and `docs/errors_fix.md` for every specific error hit and how it was diagnosed and fixed.
