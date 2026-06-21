BPF_CLANG ?= clang
BPF_SRC   := internal/tracer/tracer.bpf.c
# Built next to the binary so the runtime default (<exe-dir>/tracer.bpf.o) finds
# it without -bpf-object / $YUBIKEY_TRACER_OBJ_PATH.
BPF_OBJ   := tracer.bpf.o
BIN       := yubikey-notifier

.PHONY: all bpf clean run setcap

all: $(BIN)

# Compile the BPF C to a BPF-ELF object. -g emits the BTF the CO-RE loader needs.
$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CLANG) -O2 -g -Wall -target bpf -I/usr/include -c $< -o $@

bpf: $(BPF_OBJ)

# The binary loads the object at runtime (it is not embedded), so building the
# binary does not strictly depend on $(BPF_OBJ); we build both for convenience.
$(BIN): $(BPF_OBJ)
	go build -o $(BIN) .

# Grant the capabilities the eBPF loader needs so the binary runs unprivileged
# (as your user, with natural session-bus access). Re-run after every rebuild —
# file capabilities live on the binary and are dropped when it is replaced.
setcap: $(BIN)
	sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ./$(BIN)

# Local run. The object sits next to the binary, so the default path finds it.
# Needs root for eBPF; -E preserves DBUS_SESSION_BUS_ADDRESS/XDG_RUNTIME_DIR so
# notifications still reach your user session bus.
run: all
	sudo -E ./$(BIN) -verbose

clean:
	rm -f $(BPF_OBJ) internal/tracer/tracer.bpf.o $(BIN)
