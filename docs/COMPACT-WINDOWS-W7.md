# Compact Windows W7 baseline

The first workload uses the upstream jq 1.8.1 AMD64 Windows executable.
The CI downloads the release asset, checks its published SHA-256 and runs
it on Windows against a fixed JSON input. The exact same executable is
then passed to the existing Ryzova Kernel Compact Windows image planner
in a hosted audit. The audit captures the PE inventory and admission
result. It does not execute the image in Ryzova Kernel.

The workload reads an existing file and reports the item count and sum.
The W7 execution gate will compare the same executable's stdout, stderr
and exit status while it reads the input through a Ryzova directory grant.
The initial PR establishes the comparison inputs and reports the admission
gaps before changing runtime policy.

[Upstream jq 1.8.1 release](https://github.com/jqlang/jq/releases/tag/jq-1.8.1)
