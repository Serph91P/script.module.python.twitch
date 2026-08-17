import sys
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlencode, urlparse


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'resources' / 'lib'))
sys.modules.setdefault('requests', mock.Mock())

from twitch import keys, queries  # noqa: E402
from twitch.api import usher  # noqa: E402


CHANNEL = 'issue57_channel'
VIDEO_ID = '987654321'
HEADERS = {
    'Client-ID': 'issue57-client-id',
    'X-Playback-Test': 'audio-only-contract',
}
PLATFORM = 'issue57-web-player'
CODECS = 'av1,h265,h264,issue57'
LIVE_SIGNATURE = 'a' * 40
VOD_SIGNATURE = 'b' * 40
LIVE_TOKEN = {
    keys.SIGNATURE: LIVE_SIGNATURE,
    keys.VALUE: '{"channel":"issue57_channel","expires":1790000000}',
}
VOD_TOKEN = {
    keys.SIGNATURE: VOD_SIGNATURE,
    keys.VALUE: '{"video_id":"987654321","expires":1790000000}',
}
MANIFEST = '''#EXTM3U
#EXT-X-MEDIA:TYPE=VIDEO,GROUP-ID="chunked",NAME="1080p60 (source)"
#EXT-X-STREAM-INF:BANDWIDTH=6000000,RESOLUTION=1920x1080,FRAME-RATE=60.000,CODECS="avc1.64002A,mp4a.40.2"
https://example.invalid/issue57/chunked/index.m3u8
'''


def single_value_params(params):
    return {key: values[0] for key, values in parse_qs(params).items()}


class UsherAudioOnlyContractTests(unittest.TestCase):
    maxDiff = None

    def expected_live_params(self, allow_audio_only):
        return {
            keys.SIG: LIVE_TOKEN[keys.SIGNATURE],
            keys.TOKEN: LIVE_TOKEN[keys.VALUE],
            keys.ALLOW_SOURCE: 'true',
            keys.ALLOW_SPECTRE: 'true',
            keys.ALLOW_AUDIO_ONLY: allow_audio_only,
            keys.FAST_BREAD: 'true',
            keys.CDM: keys.WV,
            keys.REASSIGNMENT_SUPPORTED: 'true',
            keys.PLAYLIST_INCLUDE_FRAMERATE: 'true',
            keys.RTQOS: keys.CONTROL,
            keys.PLAYER_BACKEND: keys.MEDIAPLAYER,
            keys.SUPPORTED_CODECS: CODECS,
            keys.LOW_LATENCY: 'true',
        }

    def expected_vod_params(self, allow_audio_only):
        return {
            keys.NAUTHSIG: VOD_TOKEN[keys.SIGNATURE],
            keys.NAUTH: VOD_TOKEN[keys.VALUE],
            keys.ALLOW_SOURCE: 'true',
            keys.ALLOW_AUDIO_ONLY: allow_audio_only,
            keys.CDM: keys.WV,
            keys.REASSIGNMENT_SUPPORTED: 'true',
            keys.PLAYLIST_INCLUDE_FRAMERATE: 'true',
            keys.RTQOS: keys.CONTROL,
            keys.PLAYER_BACKEND: keys.MEDIAPLAYER,
            keys.BAKING_BREAD: 'true',
            keys.BAKING_BROWNIES: 'true',
            keys.BAKING_BROWNIES_TIMEOUT: '1050',
            keys.SUPPORTED_CODECS: CODECS,
        }

    def test_live_request_encodes_default_true_and_explicit_false(self):
        cases = (
            ('default', (), 'true'),
            ('explicit false', (False,), 'false'),
        )
        for label, final_args, expected_audio_only in cases:
            with self.subTest(label=label):
                with mock.patch.object(
                        usher, 'channel_token', return_value=LIVE_TOKEN) as token:
                    result = usher.live_request(
                        CHANNEL, PLATFORM, HEADERS, CODECS, True, *final_args)

                parsed = urlparse(result['url'])
                self.assertEqual(
                    'https://usher.ttvnw.net/api/channel/hls/'
                    'issue57_channel.m3u8',
                    parsed._replace(query='').geturl(),
                )
                self.assertEqual(
                    self.expected_live_params(expected_audio_only),
                    single_value_params(parsed.query),
                )
                self.assertEqual(HEADERS, result['headers'])
                token.assert_called_once_with(
                    CHANNEL, platform=PLATFORM, headers=HEADERS)

    def test_live_parser_encodes_default_true_and_explicit_false(self):
        cases = (
            ('default', (), 'true'),
            ('explicit false', (False,), 'false'),
        )
        for label, final_args, expected_audio_only in cases:
            with self.subTest(label=label):
                captured = {}

                def download(url, params, headers, data, method):
                    captured.update(
                        url=url, params=params, headers=headers,
                        data=data, method=method)
                    return MANIFEST.encode('utf-8')

                with mock.patch.object(
                        usher, 'channel_token', return_value=LIVE_TOKEN) as token:
                    with mock.patch.object(queries, 'download', side_effect=download):
                        result = usher.live(
                            CHANNEL, PLATFORM, HEADERS, CODECS, True, *final_args)

                self.assertEqual(
                    'https://usher.ttvnw.net/api/channel/hls/'
                    'issue57_channel.m3u8', captured['url'])
                self.assertEqual(
                    self.expected_live_params(expected_audio_only),
                    single_value_params(urlencode(captured['params'])),
                )
                self.assertEqual(HEADERS, captured['headers'])
                self.assertEqual({}, captured['data'])
                self.assertEqual('GET', captured['method'])
                self.assertEqual('chunked', result[0]['id'])
                self.assertEqual('avc1.64002A,mp4a.40.2', result[0]['codecs'])
                token.assert_called_once_with(
                    CHANNEL, platform=PLATFORM, headers=HEADERS)

    def test_video_request_encodes_default_true_and_explicit_false(self):
        cases = (
            ('default', (), 'true'),
            ('explicit false', (False,), 'false'),
        )
        for label, final_args, expected_audio_only in cases:
            with self.subTest(label=label):
                with mock.patch.object(
                        usher, 'vod_token', return_value=VOD_TOKEN) as token:
                    result = usher.video_request(
                        'v' + VIDEO_ID, PLATFORM, HEADERS, CODECS, *final_args)

                parsed = urlparse(result['url'])
                self.assertEqual(
                    'https://usher.ttvnw.net/vod/' + VIDEO_ID,
                    parsed._replace(query='').geturl(),
                )
                self.assertEqual(
                    self.expected_vod_params(expected_audio_only),
                    single_value_params(parsed.query),
                )
                self.assertEqual(HEADERS, result['headers'])
                token.assert_called_once_with(
                    VIDEO_ID, platform=PLATFORM, headers=HEADERS)

    def test_video_parser_encodes_default_true_and_explicit_false(self):
        cases = (
            ('default', (), 'true'),
            ('explicit false', (False,), 'false'),
        )
        for label, final_args, expected_audio_only in cases:
            with self.subTest(label=label):
                captured = {}

                def download(url, params, headers, data, method):
                    captured.update(
                        url=url, params=params, headers=headers,
                        data=data, method=method)
                    return MANIFEST.encode('utf-8')

                with mock.patch.object(
                        usher, 'vod_token', return_value=VOD_TOKEN) as token:
                    with mock.patch.object(queries, 'download', side_effect=download):
                        result = usher.video(
                            'v' + VIDEO_ID, PLATFORM, HEADERS, CODECS,
                            *final_args)

                self.assertEqual(
                    'https://usher.ttvnw.net/vod/' + VIDEO_ID,
                    captured['url'],
                )
                self.assertEqual(
                    self.expected_vod_params(expected_audio_only),
                    single_value_params(urlencode(captured['params'])),
                )
                self.assertEqual(HEADERS, captured['headers'])
                self.assertEqual({}, captured['data'])
                self.assertEqual('GET', captured['method'])
                self.assertEqual('chunked', result[0]['id'])
                self.assertEqual('avc1.64002A,mp4a.40.2', result[0]['codecs'])
                token.assert_called_once_with(
                    VIDEO_ID, platform=PLATFORM, headers=HEADERS)


if __name__ == '__main__':
    unittest.main()
