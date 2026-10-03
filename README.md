<div align="center">
	<h2>tools</h2>
</div>

[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)]()
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-0078D6.svg?style=flat-square)]()
[![Language](https://img.shields.io/badge/language-Rust%20%2B%20scripts-orange.svg?style=flat-square)]()
[![Status](https://img.shields.io/badge/status-used%20on%20hardware-brightgreen.svg?style=flat-square)]()

### The instrument rack: an evidence gate, a µs-precision EP0 cutter, a usbmon analyzer and a trace viewer.

Tooling for the A9 work — most of it built because the project kept making the *same two* mistakes, and a tool is the only thing that stops a mistake from recurring.

---

### What does this do?

| Tool | What |
|---|---|
| `arlo/a9pwn-gate.sh` | Runs the test suite with a **manifest pinned before and after**; if any pinned source moved during the run, it discards its own run as `source_changed_during_run` rather than reporting a number. Archives each run's artefact so a later run cannot erase an earlier PASS. |
| `arlo/ep0cut/` | Cuts control transfers at **µs deadlines** and sweeps `wLength` against latency, to establish when EP0 STALLs. Proved by the fact that it has failed: doctored implementations of it make named tests fail. |
| `arlo/usbmon/` | A libusb-free analyzer for usbmon captures — it cannot open a device by construction. |
| `arlo/traceview/` | Renders an a9pwn trace as the sequence of exchanges it was. |
| `arlo/usb-full-capture.sh` | Captures the **whole** URB via tcpdump, because usbmon's text interface truncates at 32 bytes — which is exactly where the registers we needed began. |
| `arlo/a9pwn-gate.{ps1,cmd}` | The Windows arm of the gate. |
| phone utilities | `discover.py`, `phone.ps1`, `backup-phone.ps1` and friends: device presence, storage, screenshots and port resets. |

---

### The failure this exists to prevent

**A check that cannot fail.** The recurring injury is a predicate that prints a confident result from no data — a verdict reading `UNMAPPED` about an address it never resolved, a capacity probe charging a reply shortfall to the command budget, a walk that says no to everything. Every tool here is built so that it **has been shown to fail**: the gate discards its own run when the tree moves, the EP0 cutter has doctored siblings that its tests catch, and the trace viewer is fed the real traces this project produced.

The second injury is **an answer thrown away**: the loader's synchronous read discarded the bytes it had received on a cancelled transfer, turning a success into an apparent timeout. `usb-full-capture.sh` exists so the wire can be read even when the tool has already mislaid the evidence.

---

### Status

These tools have been used on real hardware across a full session: the gate has caught a mid-edit race (correctly discarding its own run), the capture script recovered a trigger reply whose first 64 bytes contained the EL3 register state, and the analyzer and cutter are covered by their own negative controls.
