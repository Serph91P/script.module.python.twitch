import datetime
import hashlib
import importlib.util
import json
import re
import tempfile
import unittest
import urllib.request
import zipfile
from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / '.github' / 'workflows'
TOOLING_SHA = '7adff881ab5d0a7fc63f7474a78b2688e2e6eee4'
ADDON_ID = 'script.module.python.twitch'
ADDON_VERSION = '3.0.4'
RUNTIME_ENTRIES = ['addon.xml', 'changelog.txt', 'resources/']
PACKAGE_WORKFLOW = (
    'Serph91P/repository.serph91p/.github/workflows/'
    f'reusable-addon-package.yml@{TOOLING_SHA}'
)
NOTIFIER_WORKFLOW = (
    'Serph91P/repository.serph91p/.github/workflows/'
    f'reusable-notify-repository.yml@{TOOLING_SHA}'
)
FULL_SHA_USE = re.compile(r'^\s*uses:\s+\S+@[0-9a-f]{40}\s*$', re.MULTILINE)


class ValidationWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (WORKFLOWS / 'addon-validations.yml').read_text(
            encoding='utf-8')

    def test_parser_tests_gate_the_immutable_package_job(self):
        self.assertRegex(self.text, r'(?m)^\s{2}source-tests:\s*$')
        self.assertIn('python -m unittest discover -s tests -v', self.text)
        self.assertRegex(
            self.text,
            r'(?ms)^\s{2}package:\s*$.*?^\s{4}needs:\s+source-tests\s*$',
        )

    def test_source_tests_cannot_pollute_the_runtime_tree_with_bytecode(self):
        source_tests = self.text.split('\n  package:', 1)[0]
        self.assertRegex(
            source_tests,
            r"(?m)^\s{6}PYTHONDONTWRITEBYTECODE:\s+'1'\s*$",
        )

    def test_package_caller_is_exactly_pinned_and_configured(self):
        self.assertIn(f'uses: {PACKAGE_WORKFLOW}', self.text)
        self.assertRegex(
            self.text,
            rf'(?m)^\s{{6}}addon_id:\s+{re.escape(ADDON_ID)}\s*$',
        )
        self.assertRegex(
            self.text,
            r'''(?m)^\s{6}runtime_entries_json:\s+'''
            r'''['"]\["addon.xml","changelog.txt","resources/"\]['"]\s*$''',
        )

    def test_validation_has_no_mutable_source_checker_path(self):
        self.assertNotIn('pip install --upgrade', self.text)
        self.assertNotIn('github.com/xbmc/addon-check.git\n', self.text)
        self.assertNotRegex(self.text, r'(?m)^\s+uses:\s+\S+@v\d+')
        uses = re.findall(r'(?m)^\s*uses:\s+\S+@\S+\s*$', self.text)
        self.assertTrue(uses)
        self.assertTrue(all(FULL_SHA_USE.fullmatch(value) for value in uses), uses)

    def test_main_release_workflow_remains_unchanged(self):
        release = (WORKFLOWS / 'make-release.yml').read_bytes()
        self.assertEqual(
            hashlib.sha256(release).hexdigest(),
            '1609e1e556777f29fa37a52692e6037c52443042558683ce6f86ceb17e8f445e',
        )


class ImmutablePackageIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tooling = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tooling.cleanup)
        helper_path = Path(cls.tooling.name) / 'build_package.py'
        url = (
            'https://raw.githubusercontent.com/Serph91P/repository.serph91p/'
            f'{TOOLING_SHA}/addon-publication/build_package.py'
        )
        with urllib.request.urlopen(url, timeout=30) as response:
            helper_path.write_bytes(response.read())
        spec = importlib.util.spec_from_file_location(
            'pinned_addon_package_builder', helper_path)
        if spec is None or spec.loader is None:
            raise RuntimeError('Unable to load pinned package builder')
        cls.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.builder)

    def test_exact_runtime_package_is_deterministic_and_evidenced(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = self.builder.build_package(
                ROOT,
                Path(temporary) / 'first',
                ADDON_ID,
                RUNTIME_ENTRIES,
                123456,
                'a' * 40,
                'a' * 40,
            )
            second = self.builder.build_package(
                ROOT,
                Path(temporary) / 'second',
                ADDON_ID,
                RUNTIME_ENTRIES,
                123456,
                'a' * 40,
                'a' * 40,
            )

            first_bytes = first.package_path.read_bytes()
            second_bytes = second.package_path.read_bytes()
            checksum = hashlib.sha256(first_bytes).hexdigest()
            self.assertEqual(first_bytes, second_bytes)
            self.assertEqual(checksum, hashlib.sha256(second_bytes).hexdigest())
            self.assertEqual(first.artifact_sha256, checksum)

            expected = {
                f'{ADDON_ID}/addon.xml',
                f'{ADDON_ID}/changelog.txt',
            }
            expected.update(
                f'{ADDON_ID}/{path.relative_to(ROOT).as_posix()}'
                for path in (ROOT / 'resources').rglob('*')
                if path.is_file()
                and '__pycache__' not in path.parts
                and path.suffix not in ('.pyc', '.pyo')
            )
            with zipfile.ZipFile(first.package_path) as archive:
                members = archive.namelist()
                self.assertEqual(members, sorted(expected))
                self.assertEqual({name.split('/', 1)[0] for name in members},
                                 {ADDON_ID})
                manifest = ElementTree.fromstring(
                    archive.read(f'{ADDON_ID}/addon.xml'))
            self.assertEqual(manifest.attrib['id'], ADDON_ID)
            self.assertEqual(manifest.attrib['version'], ADDON_VERSION)
            for excluded in (
                    'tests/', '.github/', 'README', '.gitignore', '.git/'):
                self.assertFalse(any(excluded in name for name in members))

            evidence = json.loads(first.evidence_path.read_text(encoding='ascii'))
            self.assertEqual(
                evidence,
                {
                    'validation_run_id': 123456,
                    'candidate_sha': 'a' * 40,
                    'validation_head_sha': 'a' * 40,
                    'addon_id': ADDON_ID,
                    'addon_version': ADDON_VERSION,
                    'asset_name': f'{ADDON_ID}-{ADDON_VERSION}.zip',
                    'artifact_sha256': checksum,
                    'publication_id': f'{ADDON_ID}@{ADDON_VERSION}',
                },
            )


class NotifierWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (WORKFLOWS / 'notify-repository.yml').read_text(
            encoding='utf-8')

    def test_trigger_and_job_gate_bind_the_exact_successful_develop_push(self):
        self.assertRegex(self.text, r'(?m)^\s{2}workflow_run:\s*$')
        self.assertRegex(
            self.text,
            r'(?m)^\s{4}workflows:\s+\[Add-on Validations\]\s*$',
        )
        self.assertRegex(self.text, r'(?m)^\s{4}types:\s+\[completed\]\s*$')
        self.assertRegex(self.text, r'(?m)^\s{4}branches:\s+\[develop\]\s*$')
        job_condition = self.text.split('\n    runs-on:', 1)[0].rsplit(
            '\n    if: >-', 1)[1]
        for condition in (
                "github.event.workflow_run.conclusion == 'success'",
                "github.event.workflow_run.event == 'push'",
                "github.event.workflow_run.head_branch == 'develop'",
                "github.event.workflow_run.path == "
                "'.github/workflows/addon-validations.yml'"):
            self.assertIn(condition, job_condition)
        self.assertNotIn('@develop', job_condition)

    def test_notifier_calls_only_the_exact_pinned_reusable_contract(self):
        self.assertIn(f'uses: {NOTIFIER_WORKFLOW}', self.text)
        expected = {
            'source_repository':
                '${{ github.event.workflow_run.repository.full_name }}',
            'candidate_sha': '${{ github.event.workflow_run.head_sha }}',
            'validation_run_id': '${{ github.event.workflow_run.id }}',
            'validation_workflow': 'Add-on Validations',
            'validation_workflow_path':
                '.github/workflows/addon-validations.yml',
            'validation_event': 'push',
            'expected_branch': 'develop',
            'addon_id': ADDON_ID,
            'addon_version': '${{ needs.resolve.outputs.addon_version }}',
            'asset_name': '${{ needs.resolve.outputs.asset_name }}',
            'artifact_sha256':
                '${{ needs.resolve.outputs.artifact_sha256 }}',
            'publication_id': '${{ needs.resolve.outputs.publication_id }}',
        }
        for name, value in expected.items():
            self.assertRegex(
                self.text,
                rf'(?m)^\s{{6}}{name}:\s+{re.escape(value)}\s*$',
            )
        self.assertNotIn('peter-evans/repository-dispatch', self.text)
        self.assertNotIn('addon-updated', self.text)

    def test_source_read_and_dispatch_credentials_are_separated(self):
        resolve_text, notify_text = self.text.split('\n  notify-repository:', 1)
        self.assertIn('GITHUB_TOKEN: ${{ github.token }}', resolve_text)
        self.assertNotIn('REPO_DISPATCH_TOKEN', resolve_text)
        self.assertNotIn('GITHUB_TOKEN', notify_text)
        self.assertRegex(
            notify_text,
            r'(?m)^\s{4}secrets:\s*\n'
            r'\s{6}REPO_DISPATCH_TOKEN:\s+'
            r'\$\{\{ secrets\.REPO_DISPATCH_TOKEN \}\}\s*$',
        )
        self.assertNotIn('archive_download_url:', self.text)
        self.assertNotIn('client-payload:', self.text)


class PinnedNotifierIntegrationTests(unittest.TestCase):
    SOURCE = 'Serph91P/script.module.python.twitch'
    RUN_ID = 123456
    SHA = 'a' * 40
    NOW = datetime.datetime(
        2026, 7, 19, 12, 0, tzinfo=datetime.timezone.utc)

    @classmethod
    def setUpClass(cls):
        cls.tooling = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tooling.cleanup)
        helper_path = Path(cls.tooling.name) / 'notify_repository.py'
        url = (
            'https://raw.githubusercontent.com/Serph91P/repository.serph91p/'
            f'{TOOLING_SHA}/addon-publication/notify_repository.py'
        )
        with urllib.request.urlopen(url, timeout=30) as response:
            helper_path.write_bytes(response.read())
        spec = importlib.util.spec_from_file_location(
            'pinned_repository_notifier', helper_path)
        if spec is None or spec.loader is None:
            raise RuntimeError('Unable to load pinned repository notifier')
        cls.notifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.notifier)

    @classmethod
    def inputs(cls, **overrides):
        values = {
            'source_repository': cls.SOURCE,
            'candidate_sha': cls.SHA,
            'validation_run_id': cls.RUN_ID,
            'validation_workflow': 'Add-on Validations',
            'validation_workflow_path':
                '.github/workflows/addon-validations.yml',
            'validation_event': 'push',
            'expected_branch': 'develop',
            'addon_id': ADDON_ID,
            'addon_version': ADDON_VERSION,
            'asset_name': f'{ADDON_ID}-{ADDON_VERSION}.zip',
            'artifact_sha256': 'b' * 64,
            'publication_id': f'{ADDON_ID}@{ADDON_VERSION}',
        }
        values.update(overrides)
        return values

    @classmethod
    def artifact(cls, name, artifact_id, **overrides):
        value = {
            'id': artifact_id,
            'name': name,
            'expired': False,
            'created_at': '2026-07-01T12:00:00Z',
            'expires_at': '2026-07-31T12:00:00Z',
            'archive_download_url': (
                f'https://api.github.com/repos/{cls.SOURCE}/actions/'
                f'artifacts/{artifact_id}/zip'
            ),
            'workflow_run': {'id': cls.RUN_ID},
        }
        value.update(overrides)
        return value

    def test_missing_zero_duplicate_expired_and_malformed_artifacts_fail_closed(self):
        cases = [
            {'artifacts': []},
            {'artifacts': [
                self.artifact('validation-evidence', 1),
                self.artifact('addon-package', 0),
            ]},
            {'artifacts': [
                self.artifact('validation-evidence', 1),
                self.artifact('addon-package', 2),
                self.artifact('addon-package', 3),
            ]},
            {'artifacts': [
                self.artifact('validation-evidence', 1, expired=True),
                self.artifact('addon-package', 2),
            ]},
            {'artifacts': 'malformed'},
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(self.notifier.NotificationError):
                    self.notifier.find_required_artifacts(
                        lambda _url: (payload, {}),
                        self.SOURCE,
                        self.RUN_ID,
                        now=self.NOW,
                    )

    def test_pagination_is_exhaustive_and_identity_mismatches_fail_closed(self):
        next_url = (
            f'https://api.github.com/repos/{self.SOURCE}/actions/runs/'
            f'{self.RUN_ID}/artifacts?per_page=100&page=2'
        )
        pages = iter([
            (
                {'artifacts': [self.artifact('addon-package', 1)]},
                {'Link': f'<{next_url}>; rel="next"'},
            ),
            (
                {'artifacts': [self.artifact('validation-evidence', 2)]},
                {},
            ),
        ])
        selected = self.notifier.find_required_artifacts(
            lambda _url: next(pages),
            self.SOURCE,
            self.RUN_ID,
            now=self.NOW,
        )
        self.assertEqual(set(selected), {'addon-package', 'validation-evidence'})

        with self.assertRaises(self.notifier.NotificationError):
            self.notifier.validate_inputs(
                self.inputs(), 'Serph91P/other-source')
        with self.assertRaises(self.notifier.NotificationError):
            self.notifier.validate_inputs(
                self.inputs(validation_run_id=0), self.SOURCE)
        with self.assertRaises(self.notifier.NotificationError):
            self.notifier.validate_run(
                {
                    'id': self.RUN_ID,
                    'head_sha': self.SHA,
                    'name': 'Add-on Validations',
                    'path': '.github/workflows/other.yml',
                    'head_branch': 'develop',
                    'event': 'push',
                    'status': 'completed',
                    'conclusion': 'success',
                    'repository': {'full_name': self.SOURCE},
                },
                self.inputs(),
            )

    def test_dispatch_payload_is_metadata_only(self):
        payload = self.notifier.build_dispatch_payload(self.inputs())
        self.assertEqual(
            set(payload),
            {
                'source_repo',
                'candidate_sha',
                'validation_run_id',
                'validation_head_sha',
                'validation_workflow',
                'validation_workflow_path',
                'expected_branch',
                'publication_id',
            },
        )
        rendered = json.dumps(payload, sort_keys=True).lower()
        for forbidden in (
                'token', 'credential', 'asset_name', 'artifact_sha256',
                'archive_download_url', 'signed_url'):
            self.assertNotIn(forbidden, rendered)


if __name__ == '__main__':
    unittest.main()
