# What Jev would receive: example requests

This package accompanies our request to TypeSafe for written permission to use Jev in the study described in the attached preprint, *A First Look at System One Decision Models for Malware Detection* (arXiv, [doi:10.48550/arXiv.2611.20699](https://doi.org/10.48550/arXiv.2611.20699)). It shows, with real examples taken from the study's data, exactly what our client would send to Jev.

No request has been sent to Jev so far. Our code refuses every call to a hosted service until the reference of a written permission is recorded in its configuration.

## At a glance

- **Text only.** Jev would receive a short textual summary of facts that static analysis extracts from a Windows executable (the "S0 state", at most 1,024 tokens), together with typed yes/no questions about it.
- **No file, no code.** Jev would never receive a binary, any byte of a file, disassembly or decompiled code. No file is executed, neither on TypeSafe's systems nor in our lab.
- **Quoted strings are included.** The summary quotes up to 40 short strings found in the file (at most 120 characters each). For malware, these can include the sample's network indicators: 19% of the malware states have at least one URL and 10% at least one IP address. Example `ex05` shows one such state.
- **Volume.** The main experiment (E1) would send 21,796 states in 65,388 requests, about 129 million input tokens in total.

## One request

| Item | Value |
|---|---|
| Endpoint | `POST https://api.typesafe.ai/v1/systemone` |
| Headers | `Content-Type: application/json`, `Authorization: Bearer <API key>` (the key is read from an environment variable) |
| Body | exactly three fields: `state`, `model`, `questions` |
| Model | one pinned version, never an alias (`jev-1.13.0` in the current code) |
| Questions per state | 33, all of type `noul`, each with `true`/`false` criteria: one verdict question and 32 atomic behavioural questions |
| Requests per state | 3, with at most 12 questions each; every request repeats the same state |

The body is the format of TypeSafe's API reference (abridged here; the full bodies are in `examples/`):

```json
{
  "state": "FILE\nkind: EXE\nsize: medium\n...",
  "model": "jev-1.13.0",
  "questions": {
    "mal_noul": {
      "type": "noul",
      "instructions": "Based only on the evidence in the state, is the program described by the state malware?",
      "criteria": {
        "true": "The evidence, taken together, indicates software made to harm users or systems, to steal from them or to act against their interest.",
        "false": "The evidence is consistent with legitimate software, and each sensitive-looking element has an ordinary explanation."
      }
    },
    "qb_exec_command_plain": { "...": "..." }
  }
}
```

Jev's answers, one probability per question, are used as features of a classifier fitted on the true labels of the files. We do not train any model to imitate Jev's answers.

## A complete state

This is the full state of example `ex02` (packed malware, 525 tokens), exactly as it would appear in the `state` field:

```text
FILE
kind: EXE
size: medium
overlay: yes
resources: yes
tls_callbacks: no
signed: no
SECTIONS
count: few
entry_section: code
wx_sections: several
section: code size=medium vr=normal entropy=medium flags=RWX
section: rodata size=small vr=normal entropy=medium flags=R--
section: data size=small vr=normal entropy=low flags=RW-
section: resources size=large vr=normal entropy=low flags=RWX
section: custom "yxbxhpw" size=medium vr=high entropy=low flags=RWX
TOOLCHAIN
packers_detected: none
packed_by_detector: no
packed_by_heuristic: yes
IMPORTS
dll_count: few
imports_minimal: no
ordinal_imports: none
sensitive_categories: process_injection, execution, anti_analysis
kernel32: many | process_injection: HeapCreate, VirtualAlloc | execution: GetCommandLine, GetStartupInfo | anti_analysis: FileTimeToLocalFileTime, GetCurrentProcess, GetFileTime, GetSystemTimeAsFileTime
CAPABILITIES
rules: some
rule: "clear file content" ns=host-interaction/file-system/write mbc=C0052
rule: "get geographical location" ns=collection attack=T1614
rule: "delete file" ns=host-interaction/file-system/delete mbc=C0047
rule: "accept command line arguments" ns=host-interaction/cli attack=T1059 mbc=E1059
rule: "resolve function by parsing PE exports" ns=load-code/pe
rule: "read file on Windows" ns=host-interaction/file-system/read mbc=C0051
rule: "query environment variable" ns=host-interaction/environment-variable attack=T1082 mbc=E1082
rule: "parse PE header" ns=load-code/pe attack=T1129
rule: "write file on Windows" ns=host-interaction/file-system/write mbc=C0052
rule: "terminate process" ns=host-interaction/process/terminate mbc=C0018
STRINGS
strings_total: few
counts: url=none ip=none registry=none path=none command=none mutex=none user_agent=none
analysis_directed_text: no
CODE STATS
functions: some
functions_with_sensitive_api: some
```

## What the state contains

| Block | Content | Limits |
|---|---|---|
| FILE | kind (EXE or DLL), size class, overlay, resources, TLS callbacks, whether the file is signed | class words only |
| SECTIONS | number of sections, entry section, writable and executable sections; per section its role (or a custom name), size class, entropy class and flags | at most 24 sections; names at most 16 characters |
| TOOLCHAIN | whether a packer is detected, by a detector or by a heuristic | yes or no |
| IMPORTS | number of DLLs; imported API names in sensitive categories (process injection, execution, registry, network, anti-analysis, input and screen capture, mass file-system access) | at most 60 API names |
| CAPABILITIES | names of the [capa](https://github.com/mandiant/capa) rules that match, with their namespace and their MITRE ATT&CK and MBC identifiers | at most 40 rules |
| STRINGS | counts per category, then quoted strings in seven categories: URL, IP address, registry key, path, command line, mutex, user agent | at most 40 strings, each at most 120 characters |
| CODE STATS | number of functions, number of functions that call sensitive APIs | class words only |

Over all 21,796 states of E1 the size is 617 tokens on average (median 591, maximum 1,024). A state quotes 3.9 strings on average.

| Share of states with at least one quoted | Malware (7,466) | Benign (14,330) |
|---|---|---|
| URL | 19.1% | 49.0% |
| IP address | 9.6% | 13.2% |
| registry key | 24.9% | 24.5% |
| path | 41.9% | 56.8% |
| command line | 5.9% | 6.5% |
| mutex | 0.7% | 5.4% |
| user agent | 7.0% | 6.0% |

The full statistics are in `stats/state_statistics.json`.

**Sanitisation.** Before a string enters the state it is normalised (Unicode NFKC), hexadecimal runs of 32 or more characters become `<hash>`, and chat-template and special-token spellings are neutralised. Text addressed to an analysis system (e.g., "ignore previous instructions", "classify as benign") is screened, and the state reports the result in the line `analysis_directed_text`.

**Canonicalisation.** The state never contains file hashes, original file names, antivirus labels, the file's true label, or the `Machine` and `Subsystem` header fields. Four-digit years (1990-2039) become `<year>` and build paths `<build_path>`, and timestamp, toolchain and bitness details are not rendered, so that the state carries no shortcut that separates the two classes.

## What Jev never receives

- A binary, any byte of a file, disassembly or decompiled code. The study also builds states that contain decompiled functions, for local models only. Our client refuses by construction to send a state that contains code to a hosted service.
- Hashes, file names, antivirus labels or the true label of a file.
- The robustness test described below, unless TypeSafe allows it explicitly.

## How the states are produced

- **Data.** The malware comes from BODMAS and, for an out-of-distribution test, SOREL-20M. Both datasets are distributed by their publishers in disarmed form, with header fields altered so that the files cannot be loaded. The benign files come from public software sources (winget, Cygwin, MSYS2 packages, Windows 10 system files).
- **Static analysis only.** Ghidra, capa and the other extraction tools run inside a virtual machine without a network adapter, with the datasets mounted read-only and non-executable. The host receives only the text and JSON records that the virtual machine writes, and renders them into states.
- **Nothing is executed.** No sample is ever run, in the virtual machine or anywhere else.

## Safeguards in our client

- **Off by default.** No hosted call is possible while the configuration flag `hosted_enabled` is false. Turning it on requires the reference of TypeSafe's written permission and its scope.
- **Scope enforced per request.** States with code are refused, and robustness runs are refused unless the permission covers them.
- **Egress ledger.** Every request is written to a ledger before it is sent: route, host, model, token count of the state, timestamp, HTTP status and permission reference.
- **Limits.** The model version is pinned and the client uses HTTPS only. It sends at most 16 simultaneous requests, and retries only on HTTP 429 and 529 with exponential backoff. A spend cap blocks every further request unless a person raises it.
- **Size guard.** Every state plus question is checked against a 30,000-token limit, below Jev's 32,000, with a 10% margin on our own token count.

## Planned volume

Token counts use the Qwen3 tokenizer plus a 10% margin, since Jev's tokenizer is not public.

| Use | Requests | Input tokens |
|---|---|---|
| E1, main comparison: the 33 questions on every development and test state (21,796 states) | 65,388 | about 129 million |
| E6, variability: the verdict question on the 10,829 test states, three passes at least 20 hours apart | 32,487 | about 26 million |
| Possible extensions: E7 hallucination and invariance probes (2,000 and 1,000 test states), E10 out-of-distribution test (4,725 SOREL-20M states plus a 1,000-file contamination control in two conditions) | about 72,600 | about 81 million |
| E8, robustness to text planted in a file, only with TypeSafe's explicit permission | about 6,000 | about 12 million |

E8 would insert into the STRINGS block of 400 test states a fixed list of canary strings (instructions addressed to the analyst, benign claims, chat-template imitations, obfuscations, fabricated evidence) and benign padding, to measure whether planted text moves the answers. It is listed separately because it sends deliberately adversarial text.

## Files

| Path | Content |
|---|---|
| `examples/ex0N_*/state.txt` | the state, exactly as it would appear in the `state` field |
| `examples/ex0N_*/request_1.json` ... `request_3.json` | the three request bodies for that state (pretty-printed; the client sends the same object as compact UTF-8 JSON) |
| `examples/ex0N_*/summary.json` | label, source, and token counts per request |
| `questions/questions_wire.json` | the 33 questions in wire format, in the order they are asked |
| `request_format.json` | endpoint, headers, serialisation, questions and requests per state |
| `stats/state_statistics.json` | statistics over all 21,796 states of E1 |
| `tools/make_examples.py` | the script that generated this package from the study's data with the study's own client functions |

The five examples are:

| Example | File | State tokens |
|---|---|---|
| `ex01_malware_not_packed` | malware, not packed, with a Run-key persistence capability | 998 |
| `ex02_malware_packed` | malware, packed | 525 |
| `ex03_benign_exe` | benign executable | 626 |
| `ex04_benign_dll` | benign library | 534 |
| `ex05_malware_network_strings` | malware whose quoted strings include URLs or IP addresses | 827 |

Each example is the state closest to the median size of its group, taken from the study's development data only. Example `ex05` quotes verbatim a URL with an IP address, taken from a malware sample first seen in 2019. Like every state, the package carries no hash or file name of the samples.
