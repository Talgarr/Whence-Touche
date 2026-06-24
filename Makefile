BPF_CLANG ?= clang
BPF_SRC   := internal/tracer/tracer.bpf.c
BPF_OBJ   := internal/tracer/tracer.bpf.o
BIN       := whence-touche
GO_SRCS   := $(shell find . -name '*.go') go.mod go.sum
# cap_bpf + cap_perfmon + cap_sys_admin are all that's needed: they load and
# attach the eBPF probes. Agent-mediated touches (gpg-agent, ssh-agent) are
# resolved in-kernel by the request graph, so no /proc-scanning caps are required.
CAPS      := cap_bpf,cap_perfmon,cap_sys_admin+ep

# Debian/Ubuntu keep the arch-specific <asm/*.h> uapi headers under a multiarch
# triplet (e.g. /usr/include/x86_64-linux-gnu); Arch keeps them in /usr/include.
# Add the triplet dir only when it exists, so the BPF object compiles on both.
ARCH_TRIPLET := $(shell uname -m)-linux-gnu
BPF_CFLAGS   := -O2 -g -Wall -target bpf -I/usr/include \
                $(if $(wildcard /usr/include/$(ARCH_TRIPLET)/asm),-I/usr/include/$(ARCH_TRIPLET))

.PHONY: all build clean run setcap

# Default: build the binary, then grant it the eBPF caps so it runs unprivileged.
all: setcap

# Build the binary without granting caps (handy for CI / packaging).
build: $(BIN)

# Compiled next to tracer.go so the Go build can //go:embed it into the binary.
$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

# CGO_ENABLED=0 builds a pure-Go static binary, and that matters here: a cgo
# binary can't read the ELF auxv off the stack and falls back to /proc/self/auxv,
# which the file caps below make unreadable (the process is non-dumpable). Without
# auxv, cilium/ebpf can't detect the kernel version and the tracer fails to load.
# The Nix shell and goreleaser already set this; pin it so a bare `make build`
# (outside the Nix shell, with a C compiler on PATH) doesn't silently use cgo.
$(BIN): $(BPF_OBJ) $(GO_SRCS)
	CGO_ENABLED=0 go build -o $(BIN) .

# Grant eBPF caps so the binary runs unprivileged; needs sudo, re-applied per build.
setcap: $(BIN)
	sudo setcap $(CAPS) ./$(BIN)

# -E keeps the session bus so notifications reach your desktop.
run: build
	sudo -E ./$(BIN) -verbose

clean:
	rm -f $(BPF_OBJ) $(BIN)
