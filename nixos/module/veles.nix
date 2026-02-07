{ config, lib, pkgs, ... }:
let
  cfg = config.boot.initrd.veles;
  datasets-stage1 = map (pair: builtins.elemAt pair 0) cfg.settings.mounts;
  mountpoints-stage1 = map (pair: builtins.elemAt pair 1) cfg.settings.mounts;
  datasets-stage2 = map (pair: builtins.elemAt pair 0) cfg.mounts-stage2;
  mountpoints-stage2 = map (pair: builtins.elemAt pair 1) cfg.mounts-stage2;
in {
  options = {
    boot.initrd.veles =
    let
      inherit (lib) types mkEnableOption mkOption;
    in
    {
      enable = mkEnableOption "veles";

      settings = mkOption {
        description = "Veles metadata verification configuration";
        type = types.attrs;
      };
      mounts-stage2 = mkOption {
        description = "List of Stage 2 mounts for Veles to verify";
        type = types.listOf (types.listOf types.str);
        default = [];
      };
    };
  };

  config =
    let
      configPath = pkgs.writeTextFile {
        name = "veles.json";
        text = builtins.toJSON cfg.settings;
      };
      stage2ConfigPath = pkgs.writeTextFile {
        name = "veles-stage2.json";
        text = builtins.toJSON (cfg.settings // { mounts = cfg.mounts-stage2; });
      };
    in lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = config.boot.initrd.systemd.enable;
          message = "boot.initrd.systemd.enable must be enabled for veles to work";
        }
        {
          assertion = (lib.lists.intersectLists datasets-stage1 datasets-stage2) == [];
          message = "'mounts-stage2' must be disjoint from the mounts specified in the main config";
        }
      ];

      # This is handled by us.
      boot.zfs.requestEncryptionCredentials = false;

      # Do not allow automounts as they compromise security
      # and we don't need them anyway.
      systemd.services.zfs-mount.enable = false;

      boot.initrd = {
        systemd.services.veles-load = {
          after = [ "zfs-import.target" "tpm2.target" ];
          requires = [ "zfs-import.target" "tpm2.target" ];
          before = [ "sysroot.mount" ];
          requiredBy = [ "sysroot.mount" ];
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.veles}/bin/veles load --input ${configPath} --systemd_ask_password";
            KeyringMode = "inherit";
            RemainAfterExit = true;
          };
        };

        systemd.services.veles-verify = {
          after = [ "initrd-fs.target" ];
          requires = [ "initrd-fs.target" ];
          before = [ "initrd.target" ];
          requiredBy = [ "initrd.target" ];
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.veles}/bin/veles verify --input ${configPath}" +
              (lib.optionalString (datasets-stage2 != []) " --keep_keys");
            KeyringMode = "inherit";
            RemainAfterExit = true;
          };
        };

        systemd.storePaths = [
          configPath
          "${pkgs.veles}/bin/veles"
        ];
      };

      systemd.services.veles-verify-stage2 = lib.mkIf (datasets-stage2 != []) {
        after = [ "tpm2.target" ];
        requires = [ "tpm2.target" ];
        before = [ "sysinit.target" ];
        requiredBy = [ "sysinit.target" ];
        unitConfig = {
          RequiresMountsFor = mountpoints-stage2;
          # We need to start before `sysinit.target`, so
          # exclude it from our dependencies.
          DefaultDependencies = false;
        };
        path = [ pkgs.zfs ]; # Needed for getting datasets properties.
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.veles}/bin/veles verify --input ${stage2ConfigPath} " +
            "--exclude ${lib.concatStringsSep "," datasets-stage1}";
          KeyringMode = "inherit";
          RemainAfterExit = true;
        };
      };
    };
}
