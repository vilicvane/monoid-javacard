# Firmware benchmark

`scripts/benchmark` compares firmware revisions on the same physical card and reader.
It installs isolated Applets, creates known test fixtures and checks their results
before recording successful timings. Existing applications and data are preserved.

## Run

Run from the repository root with Node dependencies, `.jdk`, Java Card SDKs and
Gradle dependencies installed. Builds use the offline Gradle cache. `gp.exe` must
be available, and the test card must accept its default management keys.

Choose an exact reader and its card's eight-digit CPLC serial. Keep the card,
reader, installed suite and Authority configuration identical between runs.
Each run needs a new output directory under the ignored `.research/` directory.

```powershell
$benchmarkReader = 'ACS ACR1552 1S CL Reader PICC 0'
$benchmarkSerial = 'YOUR_CPLC_SERIAL'
$benchmarkOutput = '.research/benchmark/baseline'
$benchmarkRef = 'daac970'

node scripts/benchmark/prepare.mjs freeze --output $benchmarkOutput --ref $benchmarkRef --suite full
pwsh -NoProfile -File scripts/benchmark/build.ps1 -Output $benchmarkOutput

node scripts/benchmark/manage.mjs preflight --output $benchmarkOutput --reader $benchmarkReader --serial $benchmarkSerial
node scripts/benchmark/manage.mjs install --output $benchmarkOutput --reader $benchmarkReader --serial $benchmarkSerial
node scripts/benchmark/run.mjs --output $benchmarkOutput --reader $benchmarkReader --serial $benchmarkSerial --count 5

node scripts/benchmark/manage.mjs cleanup --output $benchmarkOutput --reader $benchmarkReader --serial $benchmarkSerial
node scripts/benchmark/manage.mjs verify --output $benchmarkOutput --reader $benchmarkReader --serial $benchmarkSerial
```

Repeat with a new output directory and the candidate revision. `freeze` resolves
the full commit, copies committed sources and records input/tool hashes. Only
package names and complete internal AIDs are remapped; production code is not
instrumented. The tool refuses occupied benchmark AIDs, changed inputs, a different
card or an unresolved operation journal. Inspect an interrupted operation before
retrying; do not replay an uncertain installation or benchmark command.

Frozen outputs also retain host source files, dependency manifests and the field-order
helper. Cleanup checks the owned card state and frozen firmware even if the host
tools have since changed; installation and execution still require matching tools.

Suites are `core`, `fido`, `otp` and `full`. Use matching smaller suites when the
card cannot hold the complete layout alongside its existing applications. Cleanup
deletes only the recorded benchmark instances and packages, then checks the
original registry.

## Authority

Installation without Authority arguments exercises APP-provided OTP time. To
exercise signed time, use the following arguments instead on a fresh installation:

```powershell
$benchmarkAuthorityKey = node --input-type=module -e "import {authorityPublicKey} from './scripts/benchmark/otp.mjs'; console.log(authorityPublicKey.toString('hex'))"

node scripts/benchmark/manage.mjs install --output $benchmarkOutput --reader $benchmarkReader --serial $benchmarkSerial --authority-public-key $benchmarkAuthorityKey --authority-url 'https://benchmark.monoid.invalid'
```

This is a public test-vector P-256 key with private scalar `1`, used only by the
isolated Identity. Time proofs are signed locally; no network request is made.
Use the same configuration for both firmware revisions. Configured and unconfigured
Authority runs are separate comparisons.

## Compare

```powershell
node scripts/benchmark/report.mjs .research/benchmark/baseline/results.json .research/benchmark/current/results.json --output .research/benchmark/comparison.md
```

The report shows baseline and current median, p90, mean, range and sample count.
It rejects mismatched cards, transports, fixtures, suites and case versions.
The default is five repeated samples; single first-use samples are reported
separately. Repeat an important comparison in reverse installation order before
attributing a difference to firmware.

Timings sum PC/SC transmit durations, including request fragments and GET RESPONSE.
Flow measurements include their SELECT and authentication commands; component
measurements cover the named stage. Nested flow and component rows overlap and
must not be added together. Host cryptographic checks, HTTP, UI and user interaction
are excluded. First-use means the first invocation of that case, not a power cycle
or a guaranteed empty cache; each result includes its specific cache assumptions.

FIDO registration and assertion series include the first operation after fixture
setup. Their five-sample distribution can therefore include a cache miss. ECDSA
also has fast and slow timing modes: a five-sample median may switch between them.
Inspect the range and individual samples before attributing a median difference
to a regression. Changing workload semantics requires a new case version.

Core covers authentication, ordinary storage, enumeration and signing. FIDO covers
PIN, registration and assertions. OTP checks three consecutive codes against
independent HMAC calculations. Older firmware uses an F201 configuration referring
to a separate HMAC item; newer firmware stores the secret in F201 itself. These
fixtures intentionally compare the same OTP operation across the two representations.

`results.json` contains samples and configuration; `events.jsonl` contains APDU
timings, lengths and status words, without payloads. A temporary printable PIN is
generated in memory. Publicly known fixtures are used, never production secrets.
Keep local GP logs and the card-ownership journal private; they include card
identifiers needed to guard installation and cleanup.

The first full D321 / ACR1552 comparison is recorded in
[benchmark baseline](../.agents/project-memory/199.md).
