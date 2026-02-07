setup() {
  bats_load_library bats-support
  bats_load_library bats-assert
  bats_load_library bats-file

  bats_require_minimum_version 1.5.0

  source "${BATS_TEST_DIRNAME}"/utils.bats

  export PROJECT_DIR="${BATS_TEST_DIRNAME}"/..
  export TEST_TMPDIR="$(temp_make --prefix 'veles-')"
  export VELES_CMD="${PROJECT_DIR}/zig-out/bin/veles"

  export SWTPM_DEVICE_PATH="${TEST_TMPDIR}/tpm0"
  export SWTPM_CTRL_PATH="${TEST_TMPDIR}/tpm0.ctrl"
  export SWTPM_STATE="${TEST_TMPDIR}/tpm-state"
  export SWTPM_PID="${TEST_TMPDIR}/swtpm.pid"

  export KEYS_FILE="${TEST_TMPDIR}/keys"

  export TEST_MOUNTS="${TEST_TMPDIR}/mounts"
  export TEST_ZFS_GET_STDOUT="${PROJECT_DIR}/tests/data/zfs-get-normal.json"
  mkdir -p "${TEST_TMPDIR}/home"
  echo "zpool/root ${TEST_TMPDIR} zfs rw,noatime,xattr,posixacl,casesensitive 0 0" > "${TEST_MOUNTS}"
  echo "zpool/home ${TEST_TMPDIR}/home zfs rw,noatime,xattr,posixacl,casesensitive 0 0" >> "${TEST_MOUNTS}"

  export SYSTEMD_ASK_PASSWORD_KEYS='zfs-zpool:password123'

  export ORIG_PATH="${PATH}"
  export PATH="${PROJECT_DIR}/tests/scripts:$PATH"
}

provision_swtpm() {
  mkdir -p "${SWTPM_STATE}"
  XDG_CONFIG_HOME="${TEST_TMPDIR}" swtpm_setup \
    --create-config-files
  XDG_CONFIG_HOME="${TEST_TMPDIR}" swtpm_setup \
    --tpm2 \
    --tpmstate "${SWTPM_STATE}" \
    --ecc \
    --create-ek-cert \
    --create-platform-cert \
    --lock-nvram \
    "$@"
}

setup_swtpm() {
  mkdir -p "${SWTPM_STATE}"
  (
    close_non_std_fds # close FDs >2
    exec 2>&- 1>&- # close remaining FDs, to prevent holding the pipe open
    exec 2>"${TEST_TMPDIR}"/swtpm-stderr.log 1>"${TEST_TMPDIR}"/swtpm-stdout.log
    swtpm socket \
      --log file=- \
      --ctrl type=unixio,path="${SWTPM_CTRL_PATH}" \
      --server type=unixio,path="${SWTPM_DEVICE_PATH}" \
      --tpmstate dir="${SWTPM_STATE}" \
      --flags not-need-init,startup-clear \
      --tpm2 \
      --daemon \
      --pid file="${SWTPM_PID}" \
      "$@"
  )
}

teardown() {
  if [[ -f "${SWTPM_PID}" ]]; then
    kill `cat ${SWTPM_PID}`
  fi
  export PATH="${ORIG_PATH}"
  chmod -R u+w "${TEST_TMPDIR}"
  temp_del "${TEST_TMPDIR}"
}

wrapped() {
  bwrap \
    --ro-bind /bin /bin \
    --ro-bind /nix /nix \
    --ro-bind /usr /usr \
    --ro-bind "${TEST_MOUNTS}" /proc/mounts \
    --bind "${TEST_TMPDIR}" "${TEST_TMPDIR}" \
    --dev /dev \
    --unshare-all \
    --new-session \
    /bin/sh -c "\"${PROJECT_DIR}\"/tests/scripts/restore-keys; $*; exit_code=\$?; \"${PROJECT_DIR}\"/tests/scripts/save-keys; exit \$exit_code"
}

veles() {
  wrapped "${VELES_CMD}" "$@"
}

get_veles_config() {
  local slot=2164260865
  local measure="\u0007\u000f"
  local extend=15
  local device="${TEST_TMPDIR}/tpm0"
  local hash_alg=11
  local pcr_hash_alg=11
  local pcr_bank_size=24
  local ecc_curve=4
  local rsa_key_bits=0
  local aes_key_bits=256
  local all_datasets="false"
  local encryption_roots='["zpool"]'
  local mounts="[[\"zpool/home\",\"${TEST_TMPDIR}/home\"],[\"zpool/root\",\"${TEST_TMPDIR}\"]]"
  for arg in "$@"; do
    arg="${arg#--*}"
    declare "${arg%=*}=${arg#*=}"
    shift
  done
  echo "{\"slot\":${slot},\"measure\":\"${measure}\",\"extend\":${extend},\"tpm\":{\"device\":\"${device}\",\
\"capabilities\":{\"hash_alg\":${hash_alg},\"pcr_hash_alg\":${pcr_hash_alg},\"pcr_bank_size\":${pcr_bank_size},\
\"ecc_curve\":${ecc_curve},\"rsa_key_bits\":${rsa_key_bits},\"aes_key_bits\":${aes_key_bits}}},\
\"all_datasets\":${all_datasets},\"encryption_roots\":${encryption_roots},\"mounts\":${mounts}}"
}
