BPF_CLANG ?= clang
BPF_SRC   := internal/tracer/tracer.bpf.c
BPF_OBJ   := internal/tracer/tracer.bpf.o
BIN       := whence-touche
GO_SRCS   := $(shell find . -name '*.go') go.mod go.sum
CAPS      := cap_bpf,cap_perfmon,cap_sys_admin+ep

.PHONY: all build clean run setcap

# Default: build the binary, then grant it the eBPF caps so it runs unprivileged.
all: setcap

# Build the binary without granting caps (handy for CI / packaging).
build: $(BIN)

# Compiled next to tracer.go so the Go build can //go:embed it into the binary.
$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CLANG) -O2 -g -Wall -target bpf -I/usr/include -c $< -o $@

$(BIN): $(BPF_OBJ) $(GO_SRCS)
	go build -o $(BIN) .

# Grant eBPF caps so the binary runs unprivileged; needs sudo, re-applied per build.
setcap: $(BIN)
	sudo setcap $(CAPS) ./$(BIN)

# -E keeps the session bus so notifications reach your desktop.
run: build
	sudo -E ./$(BIN) -verbose

clean:
	rm -f $(BPF_OBJ) $(BIN)
