# C4 SQLite progress

C4 is in progress. This change qualifies **in-memory transactions on Compact
macOS Intel and ARM64**; it does not complete file-backed SQLite or cross-platform
SQLite compatibility.

## Executed workload

The existing pinned official SQLite 3.54.1 Mach-O executables now execute:

```sql
CREATE TABLE c4_items(id INTEGER PRIMARY KEY,value INTEGER NOT NULL);
BEGIN;
INSERT INTO c4_items VALUES(1,2),(2,3),(3,5);
COMMIT;
BEGIN;
INSERT INTO c4_items VALUES(4,99);
ROLLBACK;
SELECT count(*),sum(value) FROM c4_items;
PRAGMA integrity_check;
```

Expected stdout is `3|10\nok\n`, stderr is empty, and exit status is zero.
This checks committed rows, exclusion of rolled-back rows and database integrity.
The runtime interprets the actual pinned executable; no SQL-specific shortcut
or host SQLite call is used. The database is `:memory:`.

The M92 workflow captures independent Intel/ARM macOS reference results, checks
hosted parity under UBSan, and runs the same cases after booting source-built
Ryzova in QEMU. Reference receipts and native results include source and binary
identities. A green hosted job alone does not establish native qualification.

## Runtime changes and regression checks

- AMD64: PTEST flags/alignment, PMOVZXBD, and PINSRB. PINSRB uses the low byte
  of its r32 source, including ESP/EBP/ESI/EDI without a REX prefix.
- ARM64: lane loads/insertion, REV16, scalar SIMD loads, vector widening,
  zero comparison, multiply accumulation/subtraction, ZIP2, 64-bit vector
  logical/arithmetic forms and inverted immediates.
- Explicit SSE4 tests cover flags, aliasing, extended registers, immediate lane
  masking, memory bounds, alignment, and unsupported encodings.
- ARM probes use test-only copies of the pinned image, check all output words,
  preserve untouched lanes, exercise overlapping operands, and reject reserved
  encodings. These probes also protect the overlap between widening and MOVI.

## Remaining C4 acceptance gates

| Target | Measured startup boundary before this change | Remaining work |
| --- | --- | --- |
| Linux AMD64 official SQLite | glibc loader RDTSC; a local diagnostic implementation reaches SHUFPD | Complete the measured loader/instruction/syscall requirements; qualify the common SQL workload |
| Windows AMD64 official SQLite | 4,296,192-byte executable exceeds the 4 MiB bound; diagnostic larger bound exposes unsupported PE load-config directory 10 | Validate required metadata, bounds and CRT/API behavior; qualify the common workload |
| macOS Intel/ARM64 | in-memory transaction workload now exits successfully | Implement an authorized writable file interface before qualifying persistence |

The Linux RDTSC experiment and increased Windows file bound are **not part of
this change**. Current unsupported profiles continue to fail closed.

Next gates are the same for all environments: an authorized file-backed database,
restart persistence, read-only denial without modification, transaction locking,
and interrupted-write recovery. In-memory COMMIT/ROLLBACK does not establish
those guarantees. Do not describe C4, the Linux environment, the Windows
environment, or full macOS application compatibility as complete from this work.
