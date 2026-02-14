source "${BATS_TEST_DIRNAME}"/common.bats

# Tests that don't require TPM:

@test "Shows --help" {
  run -0 veles --help
  assert_output --partial "USAGE:"
}

@test "Fails on non-existent config" {
  run -255 veles verify --input "${TEST_TMPDIR}/non-existent.json" --no_poweroff
  assert_output --partial "Failed to load Veles config"
}

@test "Fails on incorrect config" {
  echo "broken" > "${TEST_TMPDIR}/broken.json"
  run -255 veles verify --input "${TEST_TMPDIR}/broken.json" --no_poweroff
  assert_output --partial "Failed to parse Veles config"
}

@test "Fails if 'zfs get' fails" {
  export TEST_ZFS_GET_EXITCODE=1
  run -1 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json"
  assert_output --partial "Failed to call 'zfs get': exit code 1"
}

@test "Fails if 'zfs load-key' fails" {
  export TEST_ZFS_LOAD_KEY_EXITCODE=1
  run -1 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "Key verification failed"
}

@test "Fails if no ZFS datasets" {
  export TEST_ZFS_GET_STDOUT="${PROJECT_DIR}/tests/data/zfs-get-empty.json"
  run -1 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json"
  assert_output --partial "No ZFS datasets found"
}

@test "Fails if cannot write to .veles.metadata" {
  touch "${TEST_TMPDIR}"/.veles.metadata
  chmod 0400 "${TEST_TMPDIR}"/.veles.metadata
  run -1 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "for writing: AccessDenied"
}

@test "Falls back to stdin on load failure" {
  get_veles_config > "${TEST_TMPDIR}/veles.json"
  run -0 bats_pipe echo password456 \| veles load --input '${TEST_TMPDIR}/veles.json' --no_poweroff
  assert_output --partial "Keys loading failed but passwords were provided interactively"
  output=`cat "${TEST_TMPDIR}"/keys`
  assert_output << KEYS
zfs-zpool:password456
veles-manual-zpool:true
KEYS
}

@test "Falls back to systemd-ask-password on load failure" {
  get_veles_config > "${TEST_TMPDIR}/veles.json"
  run -0 veles load --input '${TEST_TMPDIR}/veles.json' --no_poweroff --systemd_ask_password
  assert_output --partial "Keys loading failed but passwords were provided interactively"
  output=`cat "${TEST_TMPDIR}"/keys`
  assert_output << KEYS
zfs-zpool:password123
veles-manual-zpool:true
KEYS
}

@test "Fails load on missing config" {
  run -255 veles load --input "${TEST_TMPDIR}/veles.json" --no_fallback --no_poweroff
  assert_output --partial "Failed to load keys"
}

@test "Fails verify on missing config" {
  run -255 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Failed to verify keys"
}

@test "Handles partial load" {
  export TEST_ZFS_GET_STDOUT="${PROJECT_DIR}/tests/data/zfs-get-different-encroots.json"
  # Provide the first key via keyring
  echo "zfs-zpool/root:passwd123" > "${TEST_TMPDIR}/keys"
  get_veles_config --encryption_roots=[\"zpool/home\",\"zpool/root\"] > "${TEST_TMPDIR}/veles.json"
  # Check that `load` will re-use the first key from keyring and
  # will ask for the second key only.
  run -0 bats_pipe echo password456 \| veles load --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Keys loading failed but passwords were provided interactively"
}

@test "Works without TPM if requested" {
  run -0 veles setup --tpm none --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  refute_output --partial "Verification properties hash"
  assert_output --partial "Writing verification config to"
  output=`cat ${TEST_TMPDIR}/veles.json`
  assert_output `get_veles_config --slot=0 --measure='' --extend=0 --device=none --hash_alg=0 --pcr_hash_alg=0 --pcr_bank_size=0 --ecc_curve=0 --rsa_key_bits=0 --aes_key_bits=0`
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Verification succeeded"
}

@test "Reuses keys from 'load' in 'verify' if requested" {
  get_veles_config > "${TEST_TMPDIR}/veles.json"
  run -0 bats_pipe echo password456 \| veles load --input '${TEST_TMPDIR}/veles.json' --no_poweroff
  assert_output --partial "Keys loading failed but passwords were provided interactively"
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Verification failed but passwords were provided interactively"
}

@test "Fails if 'verify' fails and keys were not provided" {
  get_veles_config > "${TEST_TMPDIR}/veles.json"
  export SYSTEMD_ASK_PASSWORD_KEYS=''
  run -255 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --systemd_ask_password
  assert_output --partial "Verification failed and passwords were not provided interactively"
}

@test "Succeeds if 'verify' fails but keys were provided" {
  get_veles_config > "${TEST_TMPDIR}/veles.json"
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --systemd_ask_password
  assert_output --partial "Verification failed but passwords were provided interactively"
  output=`cat "${TEST_TMPDIR}"/keys`
  # Passwords should be deleted but the marker stays.
  assert_output "veles-manual-zpool:true"
}

@test "Succeeds if 'verify' fails but keys were provided + keeps the keys" {
  get_veles_config > "${TEST_TMPDIR}/veles.json"
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --systemd_ask_password --keep_keys
  assert_output --partial "Verification failed but passwords were provided interactively"
  output=`cat "${TEST_TMPDIR}"/keys`
  assert_output << KEYS
zfs-zpool:password456
veles-manual-zpool:true
KEYS
}

# Tests with TPM:

@test "Works with default setup" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "Writing verification config to"
  assert_output --partial "Verification properties hash: 27799270f8d636ca15a1a6b416954ef3c37535ac3380192010a44943a0d4a64e"
  output=`cat ${TEST_TMPDIR}/veles.json`
  assert_output `get_veles_config`
  kill `cat ${SWTPM_PID}`
  setup_swtpm
  rm "${KEYS_FILE}"
  run -0 veles load --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Keys loading succeeded"
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Verification succeeded"
}

@test "Fails without --force on non-zero PCR" {
  setup_swtpm
  run -0 tpm2_pcrextend 15:sha256=0000000000000000000000000000000000000000000000000000000000000000 --tcti=swtpm:path="${SWTPM_DEVICE_PATH}"
  run -1 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "might be in use, refusing to extend"
}

@test "Succeeds with --force on non-zero PCR" {
  setup_swtpm
  run -0 tpm2_pcrextend 15:sha256=0000000000000000000000000000000000000000000000000000000000000000 --tcti=swtpm:path="${SWTPM_DEVICE_PATH}"
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --force --systemd_ask_password
  assert_output --partial "Writing verification config to"
}

@test "Doesn't re-create hashes if the key hasn't changed" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --force --systemd_ask_password
  assert_output --partial "Dataset 'zpool/root' has matching verification metadata already"
}

@test "Doesn't re-create hashes for the same encryption root" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "Computing new password hash for dataset 'zpool/home'"
  assert_output --partial "Reusing existing password hash for dataset 'zpool/root'"
}

@test "Re-creates hashes if the key changed" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  export SYSTEMD_ASK_PASSWORD_KEYS='zfs-zpool:passwd456'
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --force --systemd_ask_password
  assert_output --partial "Password hash for dataset 'zpool/home' doesn't verify (HashVerificationFailed), re-creating"
  assert_output --partial "Password hash for dataset 'zpool/root' doesn't verify (HashVerificationFailed), re-creating"
  assert_output --regexp  "Writing metadata .*\\.veles\\.metadata"
}

@test "Fails verification with extra mounts" {
  setup_swtpm
  run -0 veles setup --exclude zpool/home --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "Writing verification config to"
  run -255 veles verify --input "${TEST_TMPDIR}"/veles.json --no_poweroff --no_fallback
  assert_output --partial "Expected 1 mounts got 2"
}

@test "Falls back to RSA if ECC NIST is not available" {
  setup_swtpm --profile profile='{"Name":"custom","StateFormatLevel":7,"Algorithms":"rsa,hmac,aes,mgf1,keyedhash,xor,sha256,null,oaep,kdf1-sp800-56a,kdf2,kdf1-sp800-108,symcipher,cfb","Description":"test"}'
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "Writing verification config to"
  output=`cat ${TEST_TMPDIR}/veles.json`
  assert_output `get_veles_config --ecc_curve=0 --rsa_key_bits=3072`
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Verification succeeded"
}

@test "Uses ECC NIST P256 if P384 is not available" {
  setup_swtpm --profile profile='{"Name":"custom","StateFormatLevel":7,"Algorithms":"rsa,hmac,aes,mgf1,keyedhash,xor,sha256,null,oaep,kdf1-sp800-56a,kdf2,kdf1-sp800-108,symcipher,cfb,ecc,ecc-nist-p256","Description":"test"}'
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "Writing verification config to"
  output=`cat ${TEST_TMPDIR}/veles.json`
  assert_output `get_veles_config --ecc_curve=3`
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Verification succeeded"
}

@test "Encrypts ECC unsealing" {
  setup_swtpm
  export SYSTEMD_ASK_PASSWORD_KEYS='zfs-zpool:pwd123pwd123'
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --measure 16 --extend 16 --systemd_ask_password
  run -0 tpm2_pcrreset 16 --tcti=swtpm:path="${SWTPM_DEVICE_PATH}"
  rm "${KEYS_FILE}"
  run -0 veles -d load --input "${TEST_TMPDIR}"/veles.json --no_poweroff
  refute_output --partial "pwd123"
}

@test "Encrypts RSA unsealing" {
  setup_swtpm --profile profile='{"Name":"custom","StateFormatLevel":7,"Algorithms":"rsa,hmac,aes,mgf1,keyedhash,xor,sha256,null,oaep,kdf1-sp800-56a,kdf2,kdf1-sp800-108,symcipher,cfb","Description":"test"}'
  export SYSTEMD_ASK_PASSWORD_KEYS='zfs-zpool:pwd123pwd123'
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --measure 16 --extend 16 --systemd_ask_password
  run -0 tpm2_pcrreset 16 --tcti=swtpm:path="${SWTPM_DEVICE_PATH}"
  rm "${KEYS_FILE}"
  run -0 veles -d load --input "${TEST_TMPDIR}"/veles.json --no_poweroff
  refute_output --partial "pwd123"
}

@test "Works with PCR SHA-1 bank" {
  provision_swtpm --pcr-banks sha1
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "Writing verification config to"
  output=`cat ${TEST_TMPDIR}/veles.json`
  assert_output `get_veles_config --pcr_hash_alg=4`
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Verification succeeded"
}

@test "Fails with PCR SHA-384 bank only" {
  provision_swtpm --pcr-banks sha384
  setup_swtpm
  run -1 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "No supported PCR banks found"
}

@test "Fails without SHA-256 algorithm" {
  setup_swtpm --profile profile='{"Name":"custom","StateFormatLevel":7,"Algorithms":"rsa,hmac,aes,mgf1,keyedhash,xor,sha1,null,oaep,kdf1-sp800-56a,kdf2,kdf1-sp800-108,symcipher,cfb","Description":"test"}'
  run -1 veles -d setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "TPM command failed: tag=0x8001, code=0x5C3"
}

@test "Works with missing TestParm in ECC mode" {
  setup_swtpm --profile profile='{"Name":"custom","StateFormatLevel":7,"Algorithms":"","Commands":"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x189,0x18b-0x193,0x197,0x199-0x19c","Attributes":"","Description":"test"}'
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "Writing verification config to"
  output=`cat ${TEST_TMPDIR}/veles.json`
  assert_output `get_veles_config --aes_key_bits=128`
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Verification succeeded"
}

@test "Works with missing TestParm in RSA mode" {
  setup_swtpm --profile profile='{"Name":"custom","StateFormatLevel":7,"Algorithms":"rsa,hmac,aes,mgf1,keyedhash,xor,sha256,null,oaep,kdf1-sp800-56a,kdf2,kdf1-sp800-108,symcipher,cfb","Commands":"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x189,0x18b-0x193,0x197,0x199-0x19c","Attributes":"","Description":"test"}'
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "Writing verification config to"
  output=`cat ${TEST_TMPDIR}/veles.json`
  assert_output `get_veles_config --ecc_curve=0 --rsa_key_bits=2048 --aes_key_bits=128`
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Verification succeeded"
}

@test "Works with two passwords" {
  setup_swtpm
  export TEST_ZFS_GET_STDOUT="${PROJECT_DIR}/tests/data/zfs-get-different-encroots.json"
  export SYSTEMD_ASK_PASSWORD_KEYS="zfs-zpool/root:passwd123 zfs-zpool/home:passwd456"
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "Writing verification config to"
  output=`cat ${TEST_TMPDIR}/veles.json`
  assert_output `get_veles_config --encryption_roots=[\"zpool/home\",\"zpool/root\"]`
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Verification succeeded"
}

@test "Fails with too long password" {
  setup_swtpm
  run -1 bats_pipe dd if=/dev/zero bs=129 count=1 \| veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json"
  assert_output --partial "PayloadIsTooLarge"
}

@test "Selects next free slot on second call" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  output=`cat ${TEST_TMPDIR}/veles.json`
  assert_output `get_veles_config`
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --force --systemd_ask_password
  output=`cat ${TEST_TMPDIR}/veles.json`
  assert_output `get_veles_config --slot=2164260866`
}

@test "Uses specified slot on second call" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  output=`cat ${TEST_TMPDIR}/veles.json`
  assert_output `get_veles_config`
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --slot 2164260865 --force --systemd_ask_password
  output=`cat ${TEST_TMPDIR}/veles.json`
  assert_output `get_veles_config`
}

@test "Uses specified PCRs" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --measure 1,2,3 --extend 3 --systemd_ask_password
  output=`cat ${TEST_TMPDIR}/veles.json`
  assert_output `get_veles_config --measure=\"u0001,\u0002,\u0003" --extend=3`
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Verification succeeded"
}

@test "Fails with inconsistent PCRs specification" {
  setup_swtpm
  run -1 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --measure 1,2,3 --extend 4 --systemd_ask_password
  assert_output --partial "PCR 4 is not present in the list of measured PCRs 1,2,3"
}

@test "Fails with out-of-range PCRs indices" {
  setup_swtpm
  run -1 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --measure 24 --extend 24 --systemd_ask_password
  assert_output --partial "InvalidPcrIndex"
}

@test "Fails load with missing TPM state" {
  setup_swtpm
  get_veles_config > "${TEST_TMPDIR}/veles.json"
  run -0 veles -d load --input "${TEST_TMPDIR}/veles.json" --no_fallback --no_poweroff
  assert_output --partial "TPM command failed: tag=0x8001, code=0x18B"
  run -255 veles load --input "${TEST_TMPDIR}/veles.json" --no_fallback --no_poweroff
  assert_output --partial "Failed to load keys"
}

@test "Fails load with changed TPM capabilities" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --measure 16 --extend 16 --systemd_ask_password
  get_veles_config pcr_hash_alg=4 > "${TEST_TMPDIR}/veles.json"
  run -0 tpm2_pcrreset 16 --tcti=swtpm:path="${SWTPM_DEVICE_PATH}"
  run -0 veles -d load --input "${TEST_TMPDIR}/veles.json" --no_fallback --no_poweroff
  assert_output --partial "TPM command failed: tag=0x8001, code=0x99D"
  run -0 tpm2_pcrreset 16 --tcti=swtpm:path="${SWTPM_DEVICE_PATH}"
  run -255 veles load --input "${TEST_TMPDIR}/veles.json" --no_fallback --no_poweroff
  assert_output --partial "Failed to load keys"
}

@test "Fails with wrong PCRs values" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --measure 16 --extend 16 --systemd_ask_password
  run -0 tpm2_pcrreset 16 --tcti=swtpm:path="${SWTPM_DEVICE_PATH}"
  run -0 tpm2_pcrextend 16:sha256=0000000000000000000000000000000000000000000000000000000000000000 --tcti=swtpm:path="${SWTPM_DEVICE_PATH}"
  rm "${KEYS_FILE}"
  run -0 veles -d load --input "${TEST_TMPDIR}/veles.json" --no_fallback --no_poweroff
  assert_output --partial "TPM command failed: tag=0x8001, code=0x99D"
  run -0 tpm2_pcrreset 16 --tcti=swtpm:path="${SWTPM_DEVICE_PATH}"
  run -0 tpm2_pcrextend 16:sha256=0000000000000000000000000000000000000000000000000000000000000000 --tcti=swtpm:path="${SWTPM_DEVICE_PATH}"
  run -255 veles load --input "${TEST_TMPDIR}/veles.json" --no_fallback --no_poweroff
  assert_output --partial "Failed to load keys"
}

@test "Loads keys after PCR reset" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --measure 7,16 --extend 16 --systemd_ask_password
  run -0 tpm2_pcrreset 16 --tcti=swtpm:path="${SWTPM_DEVICE_PATH}"
  rm "${KEYS_FILE}"
  run -0 veles load --input "${TEST_TMPDIR}/veles.json" --no_fallback --no_poweroff
  assert_output --partial "Keys loading succeeded"
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Verification succeeded"
}

@test "Fails load with wrong ZFS passwords" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --measure 7,16 --extend 16 --systemd_ask_password
  run -0 tpm2_pcrreset 16 --tcti=swtpm:path="${SWTPM_DEVICE_PATH}"
  rm "${KEYS_FILE}"
  export TEST_ZFS_LOAD_KEY_EXITCODE=1
  run -255 veles load --input "${TEST_TMPDIR}/veles.json" --no_fallback --no_poweroff
  assert_output --partial "Failed to load keys"
}

@test "Fails verify with wrong number of mounts" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  get_veles_config --mounts="[[\"zpool/home\",\"${TEST_TMPDIR}/home\"],[\"zpool/root\",\"${TEST_TMPDIR}\"],[\"extra\",\"/extra\"]]" > "${TEST_TMPDIR}/veles.json"
  run -0 veles -d verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --no_fallback
  assert_output --partial "Expected 3 mounts got 2"
  run -255 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --no_fallback
  assert_output --partial "Failed to verify keys"
}

@test "Fails verify with wrong dataset name" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  get_veles_config --mounts="[[\"zpool/home\",\"${TEST_TMPDIR}/home\"],[\"zpool/root2\",\"${TEST_TMPDIR}\"]]" > "${TEST_TMPDIR}/veles.json"
  run -0 veles -d verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --no_fallback
  assert_output --partial "Unexpected mounted dataset 'zpool/root'"
  run -255 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --no_fallback
  assert_output --partial "Failed to verify keys"
}

@test "Fails verify with wrong mount path" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  get_veles_config --mounts="[[\"zpool/home\",\"${TEST_TMPDIR}/home\"],[\"zpool/root\",\"${TEST_TMPDIR}2\"]]" > "${TEST_TMPDIR}/veles.json"
  run -0 veles -d verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --no_fallback
  assert_output --partial "Dataset 'zpool/root' should be mounted at"
  run -255 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --no_fallback
  assert_output --partial "Failed to verify keys"
}

@test "Fails verify with missing hash file" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  rm "${TEST_TMPDIR}/.veles.metadata"
  run -0 veles -d verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --no_fallback
  assert_output --partial "Dataset 'zpool/root' verification failed"
  run -255 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --no_fallback
  assert_output --partial "Failed to verify keys"
}

@test "Fails verify with wrong properties hash" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  dd if=/dev/zero seek=1 of="${TEST_TMPDIR}"/.veles.metadata count=1 bs=1 conv=notrunc
  run -0 veles -d verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --no_fallback
  assert_output --partial "Properties verification failed for dataset 'zpool/root'"
  run -255 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --no_fallback
  assert_output --partial "Failed to verify keys"
}

@test "Fails verify with wrong password hash" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  dd if=/dev/zero seek=64 of="${TEST_TMPDIR}"/.veles.metadata count=1 bs=1 conv=notrunc
  run -0 veles -d verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --no_fallback
  assert_output --regexp "Password hash for dataset at .* was not seen yet, verifying"
  run -255 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --no_fallback
  assert_output --partial "Failed to verify keys"
}

@test "Deletes the keys after verify" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  output=`cat "${TEST_TMPDIR}"/keys`
  assert_output "zfs-zpool:password123"
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Verification succeeded"
  # `verify` should delete the keys => the file won't be created
  # in `save-keys` hook as the list of keys is empty.
  [[ ! -f "${TEST_TMPDIR}"/keys ]]
}

@test "Keeps the keys after verify if requested" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --keep_keys
  assert_output --partial "Verification succeeded"
  output=`cat "${TEST_TMPDIR}"/keys`
  assert_output "zfs-zpool:password123"
}

@test "Caches verification for the same encryption root" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  run -0 veles -d verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --regexp "Password hash for dataset at '.*/home' was not seen yet, verifying"
  assert_output --regexp "Password hash for dataset at .* has matching encryption root 'zpool'"
}

@test "Overwrites metadata if properties don't match" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  dd if=/dev/zero seek=1 of="${TEST_TMPDIR}"/.veles.metadata count=1 bs=1 conv=notrunc
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password -f
  assert_output --partial "Dataset 'zpool/home' has matching verification metadata already"
  assert_output --partial "Reusing existing password hash for dataset 'zpool/root'"
  assert_output --partial "Writing metadata "
}

@test "Overwrites metadata if password doesn't match" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  dd if=/dev/zero seek=64 of="${TEST_TMPDIR}"/.veles.metadata count=1 bs=1 conv=notrunc
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password -f
  assert_output --partial "Dataset 'zpool/home' has matching verification metadata already"
  assert_output --partial "Password hash for dataset 'zpool/root' doesn't verify (HashVerificationFailed), re-creating"
  assert_output --partial "Reusing existing password hash for dataset 'zpool/root'"
  assert_output --partial "Writing metadata "
}

@test "Calls 'zfs load-key' with correct params" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "Writing verification config to"
  output=`cat "${TEST_TMPDIR}"/.zfs-received-args`
  assert_output "load-key -L prompt -n zpool"
  output=`cat ${TEST_TMPDIR}/veles.json`
  assert_output `get_veles_config`
  kill `cat ${SWTPM_PID}`
  setup_swtpm
  rm "${KEYS_FILE}"
  run -0 veles load --input "${TEST_TMPDIR}/veles.json" --check_only --no_poweroff
  assert_output --partial "Keys loading succeeded"
  output=`cat "${TEST_TMPDIR}"/.zfs-received-args`
  assert_output "load-key -L prompt -n zpool"
  kill `cat ${SWTPM_PID}`
  setup_swtpm
  rm "${KEYS_FILE}"
  run -0 veles load --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Keys loading succeeded"
  output=`cat "${TEST_TMPDIR}"/.zfs-received-args`
  assert_output "load-key -L prompt zpool"
}

@test "Fails if datasets are swapped" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  kill `cat ${SWTPM_PID}`
  setup_swtpm
  rm "${KEYS_FILE}"
  run -0 veles load --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Keys loading succeeded"
  mv "${TEST_TMPDIR}"/.veles.metadata "${TEST_TMPDIR}"/home/.veles.metadata.new
  mv "${TEST_TMPDIR}"/home/.veles.metadata "${TEST_TMPDIR}"/.veles.metadata
  mv "${TEST_TMPDIR}"/home/.veles.metadata.new "${TEST_TMPDIR}"/home/.veles.metadata
  run -0 veles -d verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --no_fallback
  assert_output --partial "Properties verification failed for dataset 'zpool/home'"
  run -255 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff --no_fallback
  assert_output --partial "Failed to verify keys"
}

@test "Works with 'all_datasets' option" {
  setup_swtpm
  run -0 veles setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password --all_datasets
  assert_output --partial "Writing verification config to"
  assert_output --partial "Verification properties hash: cf0f5c262816757a24f6e18d6e5bd5711c7f21a280d894b77bebad45e7e78232"
  output=`cat ${TEST_TMPDIR}/veles.json`
  assert_output `get_veles_config --all_datasets=true`
  kill `cat ${SWTPM_PID}`
  setup_swtpm
  rm "${KEYS_FILE}"
  run -0 veles load --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Keys loading succeeded"
  run -0 veles verify --input "${TEST_TMPDIR}/veles.json" --no_poweroff
  assert_output --partial "Verification succeeded"
}
