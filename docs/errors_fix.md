# SentryForge (Wazuh Edition) — Errors Faced & Fixes Applied

A running log of every real error, misconfiguration, or gotcha hit during the build, and exactly how it was diagnosed and fixed. Kept separate from `explanation.md` so it can double as a troubleshooting reference and a portfolio talking point ("here's what actually went wrong and how it was debugged," not just "here's what works").

---

## Phase 1 — Environment Setup

No errors encountered. RAM reallocation and networking were confirmed correct on the first pass.

---

## Phase 2 — Wazuh Manager Installation

No errors encountered. Installation, service verification, API/dashboard checks, and the retention policy all worked as expected on the first pass.

---

## Phase 3 — Endpoint Telemetry

### Error 1 — `augenrules --load` failed with "No such file or directory" (32-bit arch rules)

- **Symptom:** Loading the Neo23x0 audit ruleset threw repeated `Error sending add rule data request (No such file or directory)` messages, referencing specific line numbers in the compiled `/etc/audit/audit.rules`.
- **Root cause:** Several rules in the Neo23x0 set specify `-F arch=b32` (32-bit syscall table). This VM's kernel is 64-bit only (`CONFIG_IA32_EMULATION` not present, confirmed via `uname -m` and absence of `/usr/include/asm/unistd_32.h`), so the kernel has no 32-bit syscall table to attach these rules to.
- **Fix:** Removed every line containing `-F arch=b32` from the **source** rules file (`/etc/audit/rules.d/audit.rules`), keeping the paired `arch=b64` rules (which already covered the same logic on this 64-bit-only system).
  ```bash
  sudo sed -i '/-F arch=b32/d' /etc/audit/rules.d/audit.rules
  sudo augenrules --load
  ```

### Error 2 — Continued load errors + `dmesg` spam: "audit rule for LSM 'crond_t' is invalid"

- **Symptom:** After fixing Error 1, `augenrules --load` still showed some errors at different line numbers. Separately, `dmesg` was being repeatedly spammed with `audit rule for LSM 'crond_t' is invalid`.
- **Root cause:** Two rules referenced `subj_type=crond_t`, a **SELinux** security label. This system uses **AppArmor**, not SELinux, so the kernel's Linux Security Module (LSM) layer has nothing to match that label against — the rule loads without an `augenrules` error, but silently fails every time it's evaluated, hence the constant `dmesg` noise.
- **Fix:** Removed both `subj_type=crond_t` lines.
  ```bash
  sudo sed -i '/subj_type=crond_t/d' /etc/audit/rules.d/audit.rules
  sudo augenrules --load
  ```

### Error 3 — Remaining load errors: rules watching non-existent tool directories

- **Symptom:** A further batch of `augenrules --load` errors, pointing at rules using `-F dir=...` or `-F exe=...`.
- **Root cause:** These rules watch directories/binaries belonging to tools not installed on this system — LVM (`/var/lock/lvm/`), Filebeat (`/etc/filebeat/`, `/usr/share/filebeat/`), and CrowdStrike Falcon (`/etc/crowdstrike/`, `/opt/CrowdStrike/`, etc.). Auditd's `-F dir=`/`-F exe=` filters resolve to a filesystem watch at load time, and fail if the target path doesn't exist. Verified every path was genuinely absent before removing anything.
- **Fix:** Removed only these specific optional-tool lines (matched by exact path, not broad pattern-matching, to avoid accidentally deleting unrelated rules like the `execve`/`process_creation` rule).
  ```bash
  sudo sed -i \
    -e '/dir=\/var\/lock\/lvm\//d' \
    -e '/dir=\/etc\/filebeat\//d' \
    -e '/dir=\/usr\/share\/filebeat\//d' \
    -e '/dir=\/etc\/crowdstrike\//d' \
    -e '/dir=\/usr\/lib\/crowdstrike\//d' \
    -e '/dir=\/opt\/CrowdStrike\//d' \
    -e '/dir=\/var\/log\/crowdstrike\//d' \
    -e '/exe=\/opt\/CrowdStrike\/falcon-sensor/d' \
    /etc/audit/rules.d/audit.rules
  sudo augenrules --load
  ```
- **End state after Errors 1–3:** `augenrules --load` completed with zero errors, 150 active rules confirmed via `auditctl -l`, `dmesg` clean after a fresh check.

### Error 4 — auditd events not reaching Wazuh at all

- **Symptom:** Even after auditd was working correctly locally, no auditd-sourced events appeared in the Wazuh dashboard — only unrelated `journald`-sourced events (sudo, useradd) were visible.
- **Root cause:** Wazuh's agent does not automatically forward arbitrary log files. It only ships what's explicitly declared as a `<localfile>` block in `ossec.conf`. No such block existed for `/var/log/audit/audit.log`.
- **Fix:** Added the missing block and restarted the agent.
  ```bash
  sudo sed -i '/<\/ossec_config>/i\
    <localfile>\
      <log_format>audit</log_format>\
      <location>/var/log/audit/audit.log</location>\
    </localfile>' /var/ossec/etc/ossec.conf
  sudo systemctl restart wazuh-agent
  ```
- **Side note (not a real error):** After this fix, the agent logged a `WARNING: Log file '/var/log/audit/audit.log' is duplicated` — meaning a default Wazuh config already had a `<localfile>` entry for the same path. Harmless (Wazuh ignores the duplicate), but worth knowing this exists by default.

### Error 5 — No alerts visible for auditd events, even after transport was confirmed working

- **Symptom:** Raw auditd data was confirmed reaching the manager (visible in the raw archive log with `<logall>` temporarily enabled), and `wazuh-logtest` confirmed correct decoding — but nothing appeared as an alert in the dashboard's Threat Hunting view.
- **Root cause:** Not actually an error — this is expected default behavior. Raw, low-level auditd syscall events match a generic, non-alerting Wazuh rule (level 0, "Audit: Messages grouped") by default. Wazuh's dashboard only displays *alerts* (level > 0), not every event that was received and parsed. This gap is exactly what the project's own custom detection rules (Phase 4 onward) are meant to fill.
- **Fix / mitigation:** No fix needed — confirmed via `wazuh-logtest` that decoding was fully correct (all `audit.*` fields populated properly), which was the actual validation gate for this phase. Understood the alerting gap as by-design, to be addressed by writing real detection rules later.

### Error 6 — Confusion: "no events from today" in Threat Hunting despite agent being active

- **Symptom:** After stopping and restarting the monitored agent, Threat Hunting appeared to show no data for "today," while the Discover tab did show a recent event — but from a different agent (`000`, the manager's own self-monitoring agent).
- **Root cause:** Two compounding factors, not a bug:
  1. The monitored agent (`soumya-3`) had genuinely been switched off overnight, so there was a real gap in its data.
  2. Wazuh names its daily indices by **UTC date**, while the VMs run on IST (UTC+5:30) — causing a mismatch between "today" on the local clock and "today" in the index name, which made the situation look more confusing than it was.
- **Fix / mitigation:** No configuration change needed. Restarted the agent, waited for it to reconnect, and confirmed fresh events appeared correctly once the agent was actually active again. Documented the UTC-vs-IST indexing behavior for future reference so it doesn't cause confusion again.

---

## Phase 4 — Manual Detection Proof-of-Concept + Converter Validation

### Error 1 — Wrong VM used when checking logs (operational mix-up, not a system bug)

- **Symptom:** Commands intended to check the monitored machine's (`soumya3`) journal/log activity were accidentally run on the manager (`soumya2`) instead, and vice versa, leading to confusing "empty" results.
- **Root cause:** Simple mix-up between the two terminal sessions — commands need to be run on the specific VM they target (e.g., generating a trigger event must happen on `soumya3`, while checking `alerts.log` happens on `soumya2`).
- **Fix / mitigation:** Re-ran each command explicitly on the correct VM, cross-checking the shell prompt (`soumya2@ubuntu` vs `soumya3@ubuntu`) each time. No system-level fix needed.

### Error 2 — Custom detection rule did not fire; a built-in rule fired instead

- **Symptom:** `wazuh-logtest` showed the built-in rule `5403` ("First time user executed sudo") firing on the test log line, instead of the custom rule (`100000`) that was supposed to match the same event.
- **Root cause:** Wazuh's built-in sudo rules are structured as **children** of a base rule `5400` (which matches `<decoded_as>sudo</decoded_as>`) using `<if_sid>5400</if_sid>`. The custom rule was written as an independent, standalone rule also trying to match `<decoded_as>sudo</decoded_as>` directly — putting it in direct competition with, and losing to, the built-in rule hierarchy (lower-ID rules evaluated first, and win when there's no parent/child relationship forcing a more specific check).
- **Fix:** Restructured the rule to be a proper child of the same base rule (`if_sid: 5400`) instead of matching the decoder directly. Updated both:
  1. The Sigma YAML rule — added a `parent_id: 5400` field.
  2. The converter script — added support for translating `parent_id` into `<if_sid>` in the generated Wazuh XML.
- **Verification:** Re-tested with `wazuh-logtest` — the custom rule (`100000`) now fired correctly on the positive case and correctly did not fire on the negative case.

### Error 3 — Manager status checked too soon after triggering a restart

- **Symptom:** Right after calling the Wazuh API's `PUT /manager/restart`, checking `systemctl status wazuh-manager` showed it still `deactivating`, and a subsequent quick check of `alerts.log` only showed a stale session-close event, causing brief concern that the deploy hadn't worked.
- **Root cause:** Not an actual failure — the manager restart simply hadn't finished cycling yet (services take ~15–20 seconds to fully stop and restart). The status and log checks were run mid-restart, before the new rule was actually loaded and active.
- **Fix / mitigation:** Waited longer (15+ seconds) before re-checking, confirmed `Active: active (running)` with all expected sub-processes present, then re-triggered the test event. Rule `100000` was confirmed firing correctly multiple times afterward.

---

## Phase 5 — Fixture Dataset Creation

### Error 1 — Fixtures were being manually transcribed instead of scripted

- **Symptom:** The process for building fixture files was: run a command on `soumya3`, look at the terminal output, paste that text into the chat, then retype it into a `cat > file << EOF` block on `soumya2`.
- **Root cause:** This is manual copy-paste through a chat window, not a reproducible extraction. It works only if every character is copied perfectly, and it's not something a CI pipeline could ever automate — it directly contradicts the guide's own intent of *scripting* fixture generation.
- **Fix:** Switched to extracting the raw log lines directly via `grep`, redirected straight into the fixture file — no manual retyping at any point.

### Error 2 — Unnecessary SSH/`scp` cross-VM copying considered

- **Symptom:** After fixing Error 1, the next instinct was to `ssh`/`scp` the raw log files from `soumya3` (monitored) over to `soumya2` (manager) to extract from there.
- **Root cause:** Overcomplication — the Wazuh agent already forwards every event from `soumya3` to `soumya2` as part of normal operation. The exact same raw log lines are already sitting locally on `soumya2`, in `alerts.log` (for anything that generated an alert) or `archives.log` (for everything, when `<logall>` is enabled).
- **Fix:** Dropped the SSH/`scp` approach entirely. All fixture extraction was done with local `grep` commands directly on `soumya2` against `alerts.log`/`archives.log`.

### Error 3 — `wazuh-manager` hung and failed after re-enabling `<logall>` and restarting

- **Symptom:** After editing `ossec.conf` to re-enable `<logall>`/`<logall_json>` (needed to capture raw auditd `execve` events for the reverse-shell fixture) and running `systemctl restart wazuh-manager`, the service failed with `Result: timeout`, and `journalctl -xeu wazuh-manager.service` showed multiple sub-processes logged as "already running" instead of being freshly started.
- **Root cause:** The `stop` phase of the restart didn't fully terminate all Wazuh sub-processes before the `start` phase began. The old processes (from before the restart) were still alive, so `start` saw them as already running and considered its job done — except something never became fully healthy, and systemd's start timeout eventually killed everything with `SIGTERM`, leaving a half-dead state. Confirmed via `ps aux | grep wazuh` showing old PIDs still present, and `free -h` showing elevated memory from the overlap.
- **Fix:** Used Wazuh's own control script for a clean, forceful stop and start instead of relying on `systemctl restart`:
  ```bash
  sudo /var/ossec/bin/wazuh-control stop
  ps aux | grep -i wazuh | grep -v grep   # confirm nothing left running
  sudo /var/ossec/bin/wazuh-control start
  ```
- **Follow-up habit adopted:** For all subsequent restarts in this phase (including reverting `<logall>` back to `no` at the end), used `wazuh-control restart` directly instead of `systemctl restart`, to avoid repeating this issue.

### Error 4 — Reverse-shell fixture extraction accidentally captured an unrelated event (recycled audit session ID)

- **Symptom:** Extracting the reverse-shell fixture by filtering on `ses=50` (the audit session ID observed during the attack) pulled back log lines from a completely unrelated, earlier SSH/cron event that had nothing to do with the reverse shell.
- **Root cause:** The Linux kernel **recycles** audit session IDs over time. `ses=50` had been used by an earlier, unrelated session hours before, and then reused again for the reverse-shell session — so filtering on it alone wasn't a unique-enough key.
- **Fix:** Re-extracted using the exact audit timestamp-second (e.g. `audit(1790410467.`) instead, which is unique to the specific burst of events generated by the actual reverse-shell trigger, confirmed against the real-time `date` output captured immediately before running the exploit.

### Error 5 — Benign fixture command produced zero auditd records

- **Symptom:** Ran `bash -c 'echo hello_from_benign_shell'` on the monitored machine as the benign counterpart to the reverse shell, then searched for it in `archives.log` — found nothing at all, even with `<logall>` confirmed enabled.
- **Root cause:** `echo` is a **bash builtin**, not an external program. Builtins run inside the existing bash process and never trigger an `execve` syscall, so auditd (which specifically watches process-creation syscalls) has nothing to record.
- **Fix:** Replaced it with a genuine external command instead (`bash -c '/bin/cat /etc/hostname'`), which correctly triggered an `execve` and was captured cleanly in `archives.log`.

---

## Phase 6 — Writing the Remaining Detection Rules

### Error 1 — Custom rule ID collided with Wazuh's own default example rule

- **Symptom:** `wazuh-logtest` printed `WARNING: Rule ID '100001' is duplicated. Only the first occurrence will be considered.` The new reverse-shell rule (assigned ID `100001` by the converter) silently never got evaluated — the event fell through to the generic base rule instead.
- **Root cause:** Wazuh ships a default `local_rules.xml` template pre-populated with an example rule using ID `100001` (a placeholder SSH-failure-from-fake-IP example, meant for users to edit). This collided directly with the low end of the converter's own reserved custom-rule range (100000–120000), which had been chosen based on Wazuh's documented "custom rule" range without checking what the default install had already claimed within it.
- **Fix:** Shifted the converter's reserved range up to 110000–120000, safely clear of Wazuh's default template IDs, rather than editing Wazuh's own default file (less portable, and a future Wazuh upgrade could reset it anyway).
  ```python
  RULE_ID_MIN, RULE_ID_MAX = 110000, 120000  # was 100000, 120000
  ```
  Reset the local `rule_id_map.json` and regenerated — existing rules were automatically renumbered into the new safe range.

### Error 2 — `grep` with a wildcard silently failed under `sudo`

- **Symptom:** `sudo grep -B5 -A5 'id="5503"' /var/ossec/ruleset/rules/*.xml` returned `grep: /var/ossec/ruleset/rules/*.xml: No such file or directory`, even though the files clearly existed.
- **Root cause:** Bash expands wildcard (`*`) patterns **before** running the command, using the *calling user's* permissions — not `sudo`'s elevated ones. Since the shell (running as the normal user) couldn't list the directory's contents to expand the glob, it passed the literal, unexpanded string `*.xml` through to `grep`, which then failed to find a file with that literal name.
- **Fix:** Wrapped the entire command (including the glob) inside `sudo bash -c "..."`, so the wildcard expansion itself also happens with elevated permissions:
  ```bash
  sudo bash -c "grep -B5 -A5 'id=\"5503\"' /var/ossec/ruleset/rules/*.xml"
  ```

### Error 3 — Python syntax error extending the converter for frequency rules

- **Symptom:** Running the patched `sigma_to_wazuh.py` failed immediately with `SyntaxError: unexpected character after line continuation character`, pointing at an f-string containing `correlation[\'frequency\']`.
- **Root cause:** The Python version in use doesn't allow a backslash-escaped quote character inside an f-string's `{...}` expression — this is a real, version-dependent Python parsing restriction, not just a typo.
- **Fix:** Extracted the dictionary lookups into plain variables *before* the f-string, avoiding any need for escaped quotes inside the expression:
  ```python
  freq = correlation['frequency']
  tframe = correlation['timeframe']
  matched_sid = correlation['if_matched_sid']
  lines = [f'  <rule id="{rule_id}" level="{level}" frequency="{freq}" timeframe="{tframe}">']
  ```

---

## Notes for later phases

- Errors from Phase 7 onward will be appended here as they occur, using the same format: **Symptom → Root cause → Fix**.
