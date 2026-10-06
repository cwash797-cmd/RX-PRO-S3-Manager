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
