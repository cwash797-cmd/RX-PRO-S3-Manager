"""Launcher safety tests: no package installation or system writes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'get.sh'


class DownloadTest(unittest.TestCase):
    def setUp(self):
        (ROOT / '.lab').mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.lab')
        self.root = Path(self.tmp.name)
        self.env = dict(os.environ, TMPDIR=str(self.root))

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, *args):
        return subprocess.run(['bash', str(SCRIPT), *args], env=self.env,
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=10)

    def test_upgrade_failure_stops_before_menu_and_is_retryable(self):
        tail = SCRIPT.read_text().split('if ! rxs3 apply-upgrade --yes; then', 1)[1]
        tail = 'if ! rxs3 apply-upgrade --yes; then' + tail
        function = 'rxs3() { if [[ $# -eq 0 ]]; then echo MENU_OPENED; else echo "$*"; return "$UPGRADE_RESULT"; fi; }; '
        for code in (0, 1):
            result = subprocess.run(['bash', '-c', function + tail], capture_output=True, text=True,
                                    env=dict(self.env, UPGRADE_RESULT=str(code)))
            self.assertEqual(result.returncode, code)
            self.assertIn('apply-upgrade --yes', result.stdout)
            self.assertEqual('MENU_OPENED' in result.stdout, code == 0)
            if code: self.assertIn('Успех не подтверждён', result.stdout)

    def test_existing_upgrade_requires_explicit_confirmation(self):
        text = SCRIPT.read_text()
        start = text.index('    if [[ -f /var/lib/rxs3/config.json ]]; then\n        echo')
        block = text[start:text.index('    apt-get update', start)]
        # Evaluate the actual confirmation block without touching production paths.
        block = block.replace('[[ -f /var/lib/rxs3/config.json ]]', 'true')
        for answer, proceeds in (('\n', False), ('нет\n', False), ('да\n', True)):
            result = subprocess.run(['bash', '-c', block + 'echo INSTALL_CONTINUES'], input=answer,
                                    capture_output=True, text=True, env=self.env)
            self.assertEqual(result.returncode, 0)
            self.assertEqual('INSTALL_CONTINUES' in result.stdout, proceeds)

    def test_help_and_shell_syntax(self):
        self.assertEqual(subprocess.run(['bash', '-n', str(SCRIPT)]).returncode, 0)
        self.assertEqual(self.run_script('--help').returncode, 0)
        self.assertNotEqual(self.run_script('--unknown').returncode, 0)

    def test_noninteractive_install_is_rejected(self):
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_destination_not_overwritten(self):
        destination = self.root / 'existing'
        destination.mkdir()
        marker = destination / 'keep'
        marker.write_text('unchanged')
        self.assertNotEqual(self.run_script('--download-only', str(destination)).returncode, 0)
        self.assertEqual(marker.read_text(), 'unchanged')

    def test_corrupt_download_not_extracted_and_temp_cleaned(self):
        bin_dir = self.root / 'bin'
        bin_dir.mkdir()
        fake = bin_dir / 'curl'
        fake.write_text('#!/bin/bash\nwhile [[ $# -gt 0 ]]; do\n'
                        'if [[ "$1" == -o ]]; then printf corrupted > "$2"; exit 0; fi\n'
                        'shift\ndone\nexit 1\n')
        fake.chmod(0o755)
        self.env['PATH'] = str(bin_dir) + os.pathsep + os.environ['PATH']
        destination = self.root / 'result'
        result = self.run_script('--download-only', str(destination))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob('rxs3-download.*')), [])


if __name__ == '__main__':
    unittest.main()
