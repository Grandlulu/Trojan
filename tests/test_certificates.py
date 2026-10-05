"""Exercise certificate workflows in a temporary directory with mocked services."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get("TEST_BASH") or (r"C:\Program Files\Git\bin\bash.exe" if os.name == "nt" else shutil.which("bash"))


def shell_path(path):
    text = Path(path).absolute().as_posix()
    return "/" + text[0].lower() + text[2:] if os.name == "nt" else text


class CertificateWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = tempfile.TemporaryDirectory(prefix="trojan-cert-fixtures-")
        cls.fixture_path = Path(cls.fixtures.name)
        for name, domain in (("valid", "trojan.example.com"), ("wrong-host", "other.example.com"), ("untrusted", "trojan.example.com")):
            cert = shell_path(cls.fixture_path / (name + ".cer"))
            key = shell_path(cls.fixture_path / (name + ".key"))
            command = f'openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN={domain} -addext subjectAltName=DNS:{domain} -keyout "{key}" -out "{cert}"'
            result = subprocess.run([BASH, "-c", command], capture_output=True, text=True, encoding="utf-8",
                                    env=dict(os.environ, MSYS2_ARG_CONV_EXCL="/CN="))
            if result.returncode:
                raise RuntimeError(result.stderr)
        command = 'openssl x509 -in "' + shell_path(cls.fixture_path / 'valid.cer') + '" -signkey "' + shell_path(cls.fixture_path / 'valid.key') + '" -days -1 -out "' + shell_path(cls.fixture_path / 'expired.cer') + '"'
        result = subprocess.run([BASH, "-c", command], capture_output=True, text=True, encoding="utf-8")
        if result.returncode:
            raise RuntimeError(result.stderr)
        (cls.fixture_path / "trusted-ca.pem").write_bytes(
            (cls.fixture_path / "valid.cer").read_bytes() + (cls.fixture_path / "wrong-host.cer").read_bytes())
        (cls.fixture_path / "empty-ca-dir").mkdir()

    @classmethod
    def tearDownClass(cls):
        cls.fixtures.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="trojan-cert-test-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.bin = self.path / "bin"
        self.bin.mkdir()
        self.cert_dir = self.path / "certificates"
        self.cert_dir.mkdir()
        self.acme_home = self.path / "acme"
        self.acme_home.mkdir()
        self.config = self.path / "server.conf"
        self.config.write_text('{"password":["keep-existing-password"]}\n')
        for target, source in (("fullchain.cer", "valid.cer"), ("private.key", "valid.key")):
            shutil.copyfile(self.fixture_path / source, self.cert_dir / target)
        self.env = dict(os.environ, TEST_SCRIPT=shell_path(ROOT / "trojan_install.sh"),
                        TEST_BIN=shell_path(self.bin), TEST_LOG=shell_path(self.path / "events"),
                        TEST_CRON=shell_path(self.path / "cron"),
                        TEST_CERT=shell_path(self.fixture_path / "valid.cer"),
                        TEST_KEY=shell_path(self.fixture_path / "valid.key"),
                        TEST_NGINX_ACTIVE="1", TEST_TROJAN_PRESENT="1", TEST_TROJAN_ACTIVE="1",
                        TEST_ISSUE_STATUS="0", TEST_INSTALL_STATUS="0", TEST_RESTART_STATUS="0",
                        TROJAN_CONFIG=shell_path(self.config), TROJAN_CERT_DIR=shell_path(self.cert_dir),
                        TROJAN_WEBROOT=shell_path(self.path / "webroot"),
                        TROJAN_ACME_HOME=shell_path(self.acme_home),
                        TROJAN_ACME_BIN=shell_path(self.acme_home / "acme.sh"),
                        SSL_CERT_FILE=str(self.fixture_path / "trusted-ca.pem"),
                        SSL_CERT_DIR=str(self.fixture_path / "empty-ca-dir"))
        self.stub("systemctl", '''
printf 'systemctl %s\n' "$*" >> "$TEST_LOG"
case "$1:$*" in
  is-active:*nginx.service*) [[ $TEST_NGINX_ACTIVE == 1 ]] ;;
  is-active:*trojan.service*) [[ $TEST_TROJAN_ACTIVE == 1 ]] ;;
  cat:*) [[ $TEST_TROJAN_PRESENT == 1 ]] ;;
  restart:*) exit "$TEST_RESTART_STATUS" ;;
  *) exit 0 ;;
esac
''')
        self.stub("nginx", 'printf "nginx %s\\n" "$*" >> "$TEST_LOG"; exit "${TEST_NGINX_STATUS:-0}"\n')
        self.stub("crontab", '''
case "$1" in
  -l) [[ -f $TEST_CRON ]] && cat "$TEST_CRON" ;;
  -) cat > "$TEST_CRON" ;;
  *) exit 1 ;;
esac
''')
        self.stub("acme.sh", '''
printf 'acme %s\n' "$*" >> "$TEST_LOG"
if [[ $1 == --issue ]]; then exit "$TEST_ISSUE_STATUS"; fi
if [[ $1 != --install-cert ]]; then exit 1; fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --key-file) key=$2; shift ;;
    --fullchain-file) cert=$2; shift ;;
    --reloadcmd) reload=$2; shift ;;
  esac
  shift
done
cp "$TEST_KEY" "$key"
cp "$TEST_CERT" "$cert"
[[ $TEST_INSTALL_STATUS == 0 ]] || exit "$TEST_INSTALL_STATUS"
bash -c "$reload"
''', self.acme_home)

    def stub(self, name, content, directory=None):
        path = (directory or self.bin) / name
        path.write_text("#!/usr/bin/env bash\n" + content, newline="\n")
        path.chmod(0o755)

    def run_shell(self, command, **overrides):
        environment = dict(self.env, **overrides)
        return subprocess.run([BASH, "-c", 'export PATH="$TEST_BIN:$PATH"; source "$TEST_SCRIPT"; ' + command],
                              env=environment, text=True, encoding="utf-8", capture_output=True, timeout=30)

    def events(self):
        path = self.path / "events"
        return path.read_text() if path.exists() else ""

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_source_does_not_start_menu_or_mutate_services(self):
        result = self.run_shell('printf ready')
        self.assert_success(result)
        self.assertEqual(result.stdout, "ready")
        self.assertEqual(self.events(), "")

    def test_success_uses_webroot_and_restarts_trojan(self):
        self.assert_success(self.run_shell('issue_and_install_certificate trojan.example.com'))
        log = self.events()
        self.assertIn("--webroot", log)
        self.assertIn("--reloadcmd", log)
        self.assertIn("systemctl restart trojan.service", log)
        self.assertNotIn("systemctl stop", log)
        self.assertNotIn("--standalone", log)
        self.assertIn("--ecc", log)
        self.assertIn("--cron", (self.path / "cron").read_text())
        if os.name != "nt":
            self.assertEqual((self.cert_dir / "private.key").stat().st_mode & 0o777, 0o600)

    def test_initial_certificate_does_not_restart_missing_service(self):
        self.assert_success(self.run_shell('issue_and_install_certificate trojan.example.com',
                                         TEST_TROJAN_PRESENT="0", TEST_TROJAN_ACTIVE="0"))
        self.assertNotIn("systemctl restart", self.events())

    def test_not_due_exit_code_installs_and_validates_existing_certificate(self):
        self.assert_success(self.run_shell('issue_and_install_certificate trojan.example.com', TEST_ISSUE_STATUS="2"))
        self.assertIn("--install-cert", self.events())

    def test_failed_issuance_keeps_old_files_and_running_nginx(self):
        before = (self.cert_dir / "fullchain.cer").read_bytes()
        result = self.run_shell('issue_and_install_certificate trojan.example.com', TEST_ISSUE_STATUS="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(before, (self.cert_dir / "fullchain.cer").read_bytes())
        self.assertNotIn("--install-cert", self.events())
        self.assertNotIn("systemctl stop", self.events())

    def test_partial_install_failure_rolls_back_cert_and_key(self):
        before = {name: (self.cert_dir / name).read_bytes() for name in ("fullchain.cer", "private.key")}
        result = self.run_shell('issue_and_install_certificate trojan.example.com', TEST_INSTALL_STATUS="1",
                                TEST_CERT=shell_path(self.fixture_path / "wrong-host.cer"),
                                TEST_KEY=shell_path(self.fixture_path / "wrong-host.key"))
        self.assertNotEqual(result.returncode, 0)
        for name, content in before.items():
            self.assertEqual(content, (self.cert_dir / name).read_bytes())

    def test_wrong_hostname_never_restarts_with_new_certificate(self):
        before = (self.cert_dir / "fullchain.cer").read_bytes()
        result = self.run_shell('issue_and_install_certificate trojan.example.com', TEST_TROJAN_ACTIVE="0",
                                TEST_CERT=shell_path(self.fixture_path / "wrong-host.cer"),
                                TEST_KEY=shell_path(self.fixture_path / "wrong-host.key"))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("systemctl restart", self.events())
        self.assertEqual(before, (self.cert_dir / "fullchain.cer").read_bytes())

    def test_key_mismatch_is_rejected(self):
        result = self.run_shell('issue_and_install_certificate trojan.example.com', TEST_TROJAN_ACTIVE="0",
                                TEST_KEY=shell_path(self.fixture_path / "wrong-host.key"))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("systemctl restart", self.events())

    def test_expired_certificate_is_rejected_before_restart(self):
        before = (self.cert_dir / "fullchain.cer").read_bytes()
        result = self.run_shell('issue_and_install_certificate trojan.example.com', TEST_TROJAN_ACTIVE="0",
                                TEST_CERT=shell_path(self.fixture_path / "expired.cer"))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("systemctl restart", self.events())
        self.assertEqual(before, (self.cert_dir / "fullchain.cer").read_bytes())

    def test_untrusted_certificate_chain_is_rejected(self):
        result = self.run_shell('issue_and_install_certificate trojan.example.com', TEST_TROJAN_ACTIVE="0",
                                TEST_CERT=shell_path(self.fixture_path / "untrusted.cer"),
                                TEST_KEY=shell_path(self.fixture_path / "untrusted.key"))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("systemctl restart", self.events())

    def test_invalid_nginx_config_never_attempts_issuance(self):
        result = self.run_shell('issue_and_install_certificate trojan.example.com', TEST_NGINX_STATUS="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("acme", self.events())

    def test_service_restart_failure_is_not_reported_as_success(self):
        result = self.run_shell('issue_and_install_certificate trojan.example.com', TEST_RESTART_STATUS="1")
        self.assertNotEqual(result.returncode, 0)

    def test_rsa_lineage_keeps_rsa_install_flags(self):
        lineage = self.acme_home / "trojan.example.com"
        lineage.mkdir()
        (lineage / "trojan.example.com.conf").touch()
        self.assert_success(self.run_shell('issue_and_install_certificate trojan.example.com'))
        self.assertIn("--keylength 2048", self.events())
        self.assertNotIn("--ecc", self.events())

    def test_standalone_lineage_is_forced_to_migrate_once(self):
        lineage = self.acme_home / "trojan.example.com_ecc"
        lineage.mkdir()
        config = lineage / "trojan.example.com.conf"
        config.write_text("Le_Webroot='no'\n")
        self.assert_success(self.run_shell('issue_and_install_certificate trojan.example.com'))
        self.assertIn("--force", self.events())
        (self.path / "events").unlink()
        config.write_text("Le_Webroot='" + self.env["TROJAN_WEBROOT"] + "'\n")
        self.assert_success(self.run_shell('issue_and_install_certificate trojan.example.com'))
        self.assertNotIn("--force", self.events())

    def test_skipped_migration_does_not_claim_repair_success(self):
        lineage = self.acme_home / "trojan.example.com_ecc"
        lineage.mkdir()
        (lineage / "trojan.example.com.conf").write_text("Le_Webroot='no'\n")
        result = self.run_shell('issue_and_install_certificate trojan.example.com', TEST_ISSUE_STATUS="2")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("--install-cert", self.events())

    def test_cron_is_idempotent_and_keeps_unrelated_jobs(self):
        cron = self.path / "cron"
        cron.write_text("5 4 * * * /usr/local/bin/backup\n")
        self.assert_success(self.run_shell('ensure_renewal_cron; ensure_renewal_cron'))
        contents = cron.read_text()
        self.assertIn("/usr/local/bin/backup", contents)
        self.assertEqual(contents.count("--cron"), 1)

    def test_invalid_domain_cannot_reach_services(self):
        for domain in ("x;reboot.example", "-bad.example", "bad..example", "example.com."):
            with self.subTest(domain=domain):
                self.assertNotEqual(self.run_shell('issue_and_install_certificate "$TEST_DOMAIN"', TEST_DOMAIN=domain).returncode, 0)
        self.assertEqual(self.events(), "")

    def test_repair_keeps_existing_password(self):
        before = self.config.read_bytes()
        self.assert_success(self.run_shell('ensure_dependencies() { :; }; ensure_acme() { :; }; repair_cert trojan.example.com'))
        self.assertEqual(before, self.config.read_bytes())

    def test_install_refuses_existing_configuration(self):
        self.assertNotEqual(self.run_shell('install_trojan trojan.example.com').returncode, 0)
        self.assertEqual(self.events(), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
