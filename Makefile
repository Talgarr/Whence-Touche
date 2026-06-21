BPF_CLANG ?= clang
BPF_SRC   := internal/tracer/tracer.bpf.c
BPF_OBJ   := tracer.bpf.o
BIN       := whence-touche
GO_SRCS   := $(shell find . -name '*.go') go.mod go.sum

.PHONY: all clean run setcap

# Single build entry (used by the PKGBUILD): BPF object + binary.
all: $(BIN)

# Built next to the binary, where the runtime default looks for it.
$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CLANG) -O2 -g -Wall -target bpf -I/usr/include -c $< -o $@

$(BIN): $(BPF_OBJ) $(GO_SRCS)
	go build -o $(BIN) .

# Grant eBPF caps so the binary runs unprivileged; re-run after each build.
setcap: $(BIN)
	sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ./$(BIN)

# -E keeps the session bus so notifications reach your desktop.
run: all
	sudo -E ./$(BIN) -verbose

clean:
	rm -f $(BPF_OBJ) $(BIN)
