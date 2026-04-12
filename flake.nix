{
  description = "yubikey-notifier — desktop notifier for yubikey-touch-detector events";

  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    version = builtins.substring 0 8 (self.lastModifiedDate or self.lastModified or "19700101");

    supportedSystems = ["x86_64-linux" "aarch64-linux"];
    forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    nixpkgsFor = forAllSystems (system: import nixpkgs {inherit system;});
  in {
    packages = forAllSystems (system: let
      pkgs = nixpkgsFor.${system};
    in {
      yubikey-notifier = pkgs.buildGoModule {
        pname = "yubikey-notifier";
        inherit version;
        src = ./.;
        vendorHash = "sha256-ytwUP34hNyFWJX8Ngrzr/H99jBLfp8DZ8AKpX1PqJh0=";

        buildInputs = with pkgs; [libnotify];

        meta = with pkgs.lib; {
          description = "Desktop notifier that shows which tool triggered a YubiKey touch request";
          license = licenses.mit;
          mainProgram = "yubikey-notifier";
          platforms = platforms.linux;
        };
      };
    });

    devShells = forAllSystems (system: let
      pkgs = nixpkgsFor.${system};
    in {
      default = pkgs.mkShell {
        nativeBuildInputs = with pkgs; [go gopls gotools];
        buildInputs = with pkgs; [libnotify];
      };
    });

    defaultPackage = forAllSystems (system: self.packages.${system}.yubikey-notifier);
  };
}
