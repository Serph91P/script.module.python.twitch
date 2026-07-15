import importlib.util
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TWITCH_MODULES = ROOT / 'resources' / 'lib' / 'twitch'
FIXTURE = ROOT / 'tests' / 'fixtures' / 'twitch_master.m3u8'


def load_parser():
    package_name = '_parser_contract_twitch'
    package = types.ModuleType(package_name)
    package.__path__ = [str(TWITCH_MODULES)]
    sys.modules[package_name] = package

    spec = importlib.util.spec_from_file_location(
        package_name + '.parser', TWITCH_MODULES / 'parser.py')
    parser = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = parser
    spec.loader.exec_module(parser)
    return parser


parser = load_parser()


class ParserCodecContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = FIXTURE.read_text(encoding='utf-8')

    def test_m3u8_to_list_preserves_variant_codec_metadata(self):
        variants = parser.m3u8_to_list(self.manifest)

        self.assertEqual(5, len(variants))
        self.assertEqual(
            {
                'id': 'chunked',
                'name': 'Source',
                'url': 'https://example.invalid/channel/chunked/index.m3u8',
                'bandwidth': 10000000,
                'fps': 60.0,
                'resolution': '1920x1080',
                'codecs': 'avc1.64002A,mp4a.40.2',
            },
            variants[0],
        )
        self.assertEqual('hvc1.1.6.L120.B0,mp4a.40.2', variants[1]['codecs'])
        self.assertEqual(59.94, variants[1]['fps'])
        self.assertIsNone(variants[2]['codecs'])
        self.assertEqual(60.0, variants[2]['fps'])
        self.assertIsNone(variants[3]['codecs'])
        self.assertEqual(30.0, variants[3]['fps'])
        self.assertEqual('Audio Only', variants[4]['name'])
        self.assertEqual('mp4a.40.2', variants[4]['codecs'])
        self.assertIsNone(variants[4]['fps'])
        self.assertIsNone(variants[4]['resolution'])

    def test_m3u8_to_dict_indexes_all_variants_without_splitting_codecs(self):
        variants = parser.m3u8_to_dict(self.manifest)

        self.assertEqual(
            ['1440p60', '480p30', '720p60', 'audio_only', 'chunked'],
            sorted(variants),
        )
        self.assertEqual(
            'hvc1.1.6.L120.B0,mp4a.40.2',
            variants['1440p60']['codecs'],
        )
        self.assertEqual('Source', variants['chunked']['name'])
        self.assertEqual('Audio Only', variants['audio_only']['name'])
        self.assertIsNone(variants['720p60']['codecs'])
        self.assertIsNone(variants['480p30']['codecs'])


if __name__ == '__main__':
    unittest.main()
