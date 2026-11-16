import asyncio
import json
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from osint_mcp import case_tools


class CaseToolsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = os.environ.get('OSINT_CASES_DB')
        os.environ['OSINT_CASES_DB'] = os.path.join(self.temp.name, 'cases.sqlite3')

    def tearDown(self):
        if self.previous is None:
            os.environ.pop('OSINT_CASES_DB', None)
        else:
            os.environ['OSINT_CASES_DB'] = self.previous
        self.temp.cleanup()

    def run_tool(self, coroutine):
        return asyncio.run(coroutine)

    def test_capture_and_resume(self):
        created = self.run_tool(case_tools.case_create('Missing painting', 'Who moved it and why?'))
        self.assertTrue(created['ok'])
        page = {'url': 'https://example.org/story?token=secret123', 'title': 'Gallery report',
                'entities': [{'type': 'domain', 'value': 'example.org'}],
                'key_sentences': ['A witness said the painting was moved to storage.']}
        captured = self.run_tool(case_tools.case_capture('Missing painting', json.dumps({'pages': [page]})))
        self.assertEqual(captured['new_mentions'], 1)
        self.assertEqual(captured['new_observations'], 1)
        self.run_tool(case_tools.case_capture('Missing painting', json.dumps({'pages': [page]})))
        found = self.run_tool(case_tools.case_search('Missing painting', 'painting'))
        self.assertEqual(len(found['observations']), 1)
        self.assertNotIn('secret123', json.dumps(found))
        self.assertEqual(len(self.run_tool(case_tools.case_list())['cases']), 1)

    def test_sourced_fact_and_unverified_lead(self):
        self.run_tool(case_tools.case_create('Investigation'))
        lead = self.run_tool(case_tools.case_add_fact('Investigation', 'Amina', 'knows', 'Youssef'))
        self.assertEqual(lead['fact']['status'], 'lead')
        again = self.run_tool(case_tools.case_add_fact('Investigation', 'Amina', 'knows', 'Youssef'))
        self.assertEqual(again['fact']['id'], lead['fact']['id'])
        fact = self.run_tool(case_tools.case_add_fact('Investigation', 'Amina', 'visited', 'Rabat',
            object_kind='place', source_url='https://example.org/report', evidence='Amina visited Rabat.'))
        self.assertEqual(fact['fact']['status'], 'sourced')
        graph = self.run_tool(case_tools.case_graph('Investigation', 'Amina'))
        self.assertEqual(len(graph['facts']), 2)
        self.assertEqual(sum(edge['type'] == 'fact' for edge in graph['edges']), 2)
        self.assertTrue(any(node['name'] == 'Rabat' for node in graph['nodes'] if node['type'] == 'entity'))

    def test_research_auto_capture(self):
        self.run_tool(case_tools.case_create('Case X'))
        result = {'ok': True, 'pages': [{'url': 'https://example.com/report', 'title': 'Report',
                  'entities': [{'type': 'person', 'value': 'Amina'}],
                  'key_sentences': ['Amina was named in the report.']}]}
        with patch('osint_mcp.deep_tools.deep_osint', new=AsyncMock(return_value=result)):
            saved = self.run_tool(case_tools.case_research('Case X', 'Amina'))
        self.assertEqual(saved['capture']['new_mentions'], 1)
        self.assertEqual(len(self.run_tool(case_tools.case_graph('Case X'))['observations']), 1)

    def test_unsourced_note_persists(self):
        self.run_tool(case_tools.case_create('Case Z'))
        note = self.run_tool(case_tools.case_note('Case Z', 'Rabat', 'place', 'A possible meeting location'))
        self.assertEqual(note['status'], 'lead')
        found = self.run_tool(case_tools.case_search('Case Z', 'meeting'))
        self.assertEqual(len(found['observations']), 1)
        graph = self.run_tool(case_tools.case_graph('Case Z', 'Rabat'))
        self.assertEqual(len(graph['observations']), 1)

    def test_reject_invalid_source(self):
        self.run_tool(case_tools.case_create('Case Y'))
        result = self.run_tool(case_tools.case_add_fact('Case Y', 'A', 'knows', 'B',
            source_url='file:///etc/passwd'))
        self.assertFalse(result['ok'])


if __name__ == '__main__':
    unittest.main()
