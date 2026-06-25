{
  description = "Whence Touché — eBPF YubiKey touch notifier: build toolchain + e2e tool environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      # eBPF (and this tool) are Linux-only.
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      # `nix develop` drops you into a shell that can BUILD the tool and RUN
      # every tool the classifier supports, so e2e/run.sh exercises each one.
      devShells = forAllSystems (pkgs:
        let
          # Toolchain to compile the embedded eBPF object and the Go binary.
          # clang-unwrapped is the raw compiler: the cc-wrapper injects host
          # sysroot/-march flags that fight `-target bpf`.
          buildTools = [
            pkgs.go
            pkgs.gnumake
            pkgs.llvmPackages.clang-unwrapped
            pkgs.libbpf       # <bpf/bpf_helpers.h>, <bpf/bpf_core_read.h>
            pkgs.linuxHeaders # <linux/bpf.h>, <asm/*>
          ];

          # One package per supported tool (see internal/classifier/rules), so
          # the harness can drive a real operation through each.
          supportedTools = [
            pkgs.gnupg              # gpg / gpg2 (+ scdaemon talks to the YubiKey)
            pkgs.openssh            # ssh / scp / sftp / ssh-keygen (FIDO sk-*)
            pkgs.pass               # password-store
            pkgs.gopass             # gopass
            pkgs.sops               # sops
            pkgs.age                # age
            pkgs.rage               # rage
            pkgs.git                # git
            pkgs.keepassxc          # keepassxc / keepassxc-cli
            pkgs.yubikey-manager    # ykman (key diagnostics)
            pkgs.age-plugin-yubikey # age + YubiKey via PIV
            pkgs.libfido2           # fido2-token etc. for FIDO diagnostics
            pkgs.xdg-utils          # xdg-open — launch the browser for the WebAuthn test
          ];
        in
        {
          default = pkgs.mkShell {
            packages = buildTools ++ supportedTools;

            # The Makefile defaults BPF includes to host paths (/usr/include),
            # which don't exist under Nix. Point the BPF compile at the Nix
            # headers instead; the Makefile honours these via `?=`.
            BPF_CLANG = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";
            BPF_CFLAGS = "-O2 -g -Wall -target bpf -I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include";

            # cilium/ebpf is pure Go; keep the build cgo-free and reproducible.
            CGO_ENABLED = "0";

            shellHook = ''
              # A host version manager (mise, asdf, …) can shadow `go` on PATH or
              # leak a GOROOT into this shell, which yields
              #   compile: version "goX" does not match go tool version "goY"
              # because the `go` binary and $GOROOT/tools come from different Go
              # installs. Force this shell's Go toolchain to win and stay
              # self-consistent.
              unset GOROOT
              export PATH="${pkgs.go}/bin:$PATH"
              export GOTOOLCHAIN=local

              echo "whence-touche dev shell"
              echo "  build : make build"
              echo "  e2e   : ./e2e/run.sh   (needs a real YubiKey + sudo for eBPF caps)"
            '';
          };
        });
    };
}
