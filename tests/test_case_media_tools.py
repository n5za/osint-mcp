import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from PIL import Image

from osint_mcp import case_media_tools as media
from osint_mcp import case_tools


class CaseMediaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = os.environ.get('OSINT_CASES_DB')
        os.environ['OSINT_CASES_DB'] = str(Path(self.temp.name) / 'cases.sqlite3')
        self.image = Path(self.temp.name) / 'photo.png'
        Image.new('RGB', (120, 80), 'blue').save(self.image)
        asyncio.run(case_tools.case_create('Photo case'))

    def tearDown(self):
        if self.previous is None:
            os.environ.pop('OSINT_CASES_DB', None)
        else:
            os.environ['OSINT_CASES_DB'] = self.previous
        self.temp.cleanup()

    def run_tool(self, value):
        return asyncio.run(value)

    def test_person_folder_and_graph(self):
        added = self.run_tool(media.case_image_add('Photo case', str(self.image), person='Amina', ocr=False))
        self.assertTrue(added['ok'])
        self.assertTrue(Path(added['person_folder']).exists())
        self.assertTrue(Path(added['person_folder'], 'profile.json').exists())
        viewed = self.run_tool(media.case_image_view('Photo case', added['image_id']))
        self.assertEqual(str(viewed.path), added['path'])
        crop = self.run_tool(media.case_image_crop('Photo case', added['image_id'], 10, 10, 70, 60, person='Amina'))
        self.assertTrue(crop['ok'])
        self.assertEqual(crop['crop_of_image_id'], added['image_id'])
        self.assertTrue(self.run_tool(media.case_image_similar('Photo case', added['image_id']))['matches'])
        profile = self.run_tool(media.person_dossier('Photo case', 'Amina'))
        self.assertTrue(Path(profile['profile']).exists())
        self.assertEqual(len(profile['images']), 2)
        graph = self.run_tool(case_tools.case_graph('Photo case', 'Amina'))
        self.assertTrue(any(edge['type'] == 'image_reference' for edge in graph['edges']))
        reverse = self.run_tool(media.case_image_reverse('Photo case', added['image_id']))
        self.assertTrue(reverse['needs_key'])
        self.assertEqual(reverse['matches'], [])

    def test_account_candidate_is_only_a_lead(self):
        candidate = media._account_candidate('https://x.com/sample/status/123')
        self.assertEqual(candidate['handle'], 'sample')
        self.assertIn('not_verified', candidate['status'])
        self.assertIsNone(media._account_candidate('https://instagram.com/p/123'))

    def test_tineye_backlink_saved(self):
        added = self.run_tool(media.case_image_add('Photo case', str(self.image), ocr=False))
        match = {'ok': True, 'stats': {'total_results': 1}, 'matches': [
            {'domain': 'example.org', 'score': 90, 'tags': [], 'backlinks': [
                {'page_url': 'https://example.org/post', 'image_url': 'https://example.org/photo.jpg', 'crawl_date': '2026-01-01'}
            ]}
        ]}
        with patch.object(media, 'api_key', return_value='test-key'), patch.object(media, '_tineye_search', new=AsyncMock(return_value=match)):
            found = self.run_tool(media.case_image_reverse('Photo case', added['image_id']))
        self.assertEqual(found['new_source_links'], 1)
        graph = self.run_tool(case_tools.case_graph('Photo case'))
        self.assertTrue(any(edge['type'] == 'image_seen_on' for edge in graph['edges']))


if __name__ == '__main__':
    unittest.main()
