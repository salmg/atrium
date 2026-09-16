# Paper

Two documents, same subject, different registers.

| File | Register | Length |
|---|---|---|
| `atrium-internals.html` | Field guide — plain-language on top, spec detail underneath, exhibits over argument | ~6,000 words |
| `atrium-semantic-divergence.html` | Two-column academic preprint — thesis, contributions, related work, evaluation | ~16,300 words |

Both are self-contained: no build step, no assets beyond web fonts.

---

## `atrium-internals.html`

**ATRIUM Internals.** Written for two readers at once: someone meeting EMV for
the first time, and someone who already knows it and wants the byte-level
detail. It runs top-down — what the tool is, why the framework parts are worth
having separately, then progressively further under the hood.

Two structural devices do that work. Green **plain-language boxes** carry the
one-line version of whatever was just explained, so a new reader can skip the
detail and keep the thread. The **left rail** carries the spec citations for
each section, so an advanced reader can go straight to the source.

The status board sits at § 04, before any mechanism is described, so what has
run on hardware and what has only run against test doubles is settled up front.
§ 14 is a *Be Aware* section in the blog idiom: the setup traps and the limits
the tool puts on itself.

Modelled on the companion note *Card Relay Internals*, which covers the
SimTrace2 relay this project's contact side runs on. Set in **STIX Two Text**
with **IBM Plex Mono** for hex. One accent hue (a mid blue) marks the byte or
component under discussion; green and dark red are reserved for confirmed and
defective. No source-code listings — the exhibits are diagrams, byte strips,
wire transcripts and tool output.

Exhibits: a two-boundary overview, the DE4/9F02 byte strip, the intercept
pipeline, byte strips for the T=0 repadding and the ATR rewrite, the four host
rungs, a verification report, the real T=1 transaction transcript, and a table
of what remains unproven.

## `atrium-semantic-divergence.html`

**Detecting Semantic Divergence Across Payment Layers: cross-layer,
message-level fault injection for EMV cards, terminals, communication links and
authorisation hosts.**

Argument first: the thesis, the four properties an instrument needs to test
for it, the eleven technical contributions, six worked examples, and the
evaluation against the properties.

Set in the Croscore metric-compatible trio, so it measures like a Times /
Helvetica / Courier manuscript: **Tinos** (Times New Roman metrics) for body
and headings, **Arimo** (Arial/Helvetica) for figure and table labels, and
**Courier Prime** for code and hex. Body is black on white; two hues are
reserved and carry meaning wherever they appear — navy for the mechanism under
discussion, dark red for the divergence the report is about.

Section numbering is Arabic with `§` cross-references, the ACM/USENIX
convention. If you need IEEE house style instead (Roman numerals, `Section
VII-C` cross-references), that is a mechanical conversion of the headings and
the ~40 in-text references.

## Producing a PDF

Print the page (`Ctrl/Cmd-P`) and save as PDF. The print stylesheet sets A4
with 15 mm margins, drops the screen chrome, and forces the light palette, so
the output is a conventional two-column preprint.

```bash
# headless, if you prefer
chromium --headless --print-to-pdf=atrium-paper.pdf \
         --no-pdf-header-footer paper/atrium-semantic-divergence.html
```

`atrium-internals.html` prints as a single-column A4 document; its print
stylesheet unrolls the scroll containers so the byte strips and the transcript
are not clipped.

## Keeping it accurate

The measurements in both documents (line counts, 787 tests, 332 of them on
the host side, the twenty-eight suites in Table V) were taken at revision
`e50d96e`. Reproduce them with:

```bash
python3 -m pytest            # 787 tests (13 need pyscard)
python3 -m host.cli selftest # crypto self-test and its stated limits
find . -name '*.py' -not -path './.git/*' | xargs wc -l | tail -1
find host -name '*.py' -not -path '*/tests/*' | xargs wc -l | tail -1
```

`pycryptodome` is required — it comes from the root `requirements.txt`. Without
it the whole cryptography suite fails on an import error rather than skipping.

Update the masthead revision, §12 and Table V in the preprint, and § 04 of
`atrium-internals.html`, together when the numbers move.

## A note on terminology

"Fault injection" here means **message-level** (interface) fault injection:
every injected fault is a well-formed message carrying a wrong value, so what
is exercised is the receiver's policy rather than its parser. It is *not*
glitching — voltage, clock or laser — which is what the term most often means
in the smart-card literature. §3.1 states this explicitly under P1, since a
reader from that community would otherwise expect the wrong thing.

## Scope note

The contact relay runs on **SimTrace2** — its hardware, card-emulation
firmware and host tool (`simtrace2-remsim`) are the foundation, not a
comparison point. §6.4 and Fig. 6 describe what this project adds on top: a
T=1 block layer in the firmware and an in-flight ATR rewrite in the host
tool. That code lives in a second repository in the same toolchain (a fork of
SimTrace2 tracking upstream 0.8.x); §15 says so, and reference [15] is the
companion note `Card Relay Internals`, which carries the build detail, the
captured transaction and the relay's own ledger of what is still unproven.

## Before submitting anywhere

- Citation metadata in the reference list is from memory and should be checked
  against the originals (venue, year, page numbers) before submission.
- Authorship is attributed to the repository owner; add affiliation, ORCID and
  contact details as the venue requires.
