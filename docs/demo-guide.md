# PacketScope 2–3 minute demonstration

This script is intended for a live competition recording or a reviewer who
already has Python 3.12.7 and Chromium installed. It uses only the built-in,
deterministic captures; no packet data leaves the local machine.

## 0:00–0:20 — Start locally

```bash
make serve
```

Open <http://127.0.0.1:8765>. Point out the **LOCAL-ONLY / EVIDENCE FIRST**
header and the **No cloud · No telemetry** badge.

## 0:20–0:55 — Load evidence and inspect a hypothesis

1. Select **CRC-16 / big-endian** and click **Load demo**.
2. Confirm the summary shows **8 packets** and candidate hypotheses.
3. Click a counter or length hypothesis. The HEX pane highlights the bytes and
   the evidence panel shows offsets, evidence quality, and caveats.
4. Say explicitly that the result is a ranked hypothesis, not a confirmed fact.

## 0:55–1:25 — Compare messages and inspect checksums

1. Open **Compare**, keep three packets selected, and click **Next diff**.
2. Open **Fields** to show aligned locations across packets.
3. Open **CRC** to show the CRC-16 candidate and its sample count.

## 1:25–1:55 — Record and edit human context

1. Return to **Overview**, enter `message header`, start `0`, width `1`, and
   click **Add annotation**.
2. Click **Edit**, change the label to `reviewed header`, start to `1`, and
   width to `2`; click **Update annotation**.
3. Use Ctrl+Z and Ctrl+Y to show that field editing is undoable and redoable.

## 1:55–2:25 — Export, apply, and evaluate

1. Click **Export protocol schema**, then choose that downloaded JSON in
   **Apply protocol schema**. The status should say **Applied protocol schema
   to 8 packet(s)** and the Fields tab should show the applied schema values.
2. Click **Evaluate reference**. The result is marked **Trusted server
   reference** and appears only after the investigation is requested.
3. Optionally switch to **CRC-32 / little-endian + overflow** and point out
   that the same workflow handles the second deterministic profile.

## Screenshot evidence

The real Chromium E2E suite creates these application screenshots (ignored
locally so captures never become repository fixtures):

- `test-artifacts/playwright/phase5-opens-navigates-and-c0493-inistic-demo-investigations/demo-crc32-real-browser.png`
- `test-artifacts/playwright/phase5-downloads-reimports-b4622-multi-flow-capture-by-scope/multiflow-reanalysis.png`

To regenerate them with the pinned local server and browser test dependency:

```bash
PACKETSCOPE_PYTHON=./.runtime/cpython-3.12.7-linux-x86_64-gnu/bin/python3.12 npm run e2e
```

Review the images before attaching them to a competition submission. Do not
attach packet downloads, project JSON, traces, or console artifacts.
