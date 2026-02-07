source "${BATS_TEST_DIRNAME}"/common.bats

@test "Works with default setup" {
  setup_swtpm
  run -0 veles -d setup --tpm "${SWTPM_DEVICE_PATH}" --output "${TEST_TMPDIR}/veles.json" --systemd_ask_password
  assert_output --partial "Verification properties hash: 27799270f8d636ca15a1a6b416954ef3c37535ac3380192010a44943a0d4a64e"
  assert_output --partial "Writing verification config to"
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
