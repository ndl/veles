{ config, pkgs, ... }: {
  boot.initrd.veles = {
    enable = true;
    settings = {
      slot = 2164260865;
      measure = [7 8 9 10 11 12 13 14 15];
      extend = 15;
      tpm = {
        device = "/dev/tpmrm0";
        capabilities = {
          hash_alg = 11;
          pcr_hash_alg = 11;
          pcr_bank_size = 24;
          ecc_curve = 4;
          rsa_key_bits = 0;
          aes_key_bits = 256;
        };
      };
      all_datasets = true;
      encryption_roots = [ "rpool" ];
      mounts = [
        [ "rpool/system" "/sysroot" ]
        [ "rpool/system/var" "/sysroot/var" ]
        [ "rpool/system/nix" "/sysroot/nix" ]
        [ "rpool/system/nix/store" "/sysroot/nix/store" ]
      ];
    };
    mounts-stage2 = [
      [ "rpool/data/home" "/home" ]
      [ "rpool/system/nix/var" "/nix/var" ]
    ];
  };
}
