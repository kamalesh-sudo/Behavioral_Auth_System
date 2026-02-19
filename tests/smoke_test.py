import asyncio
import unittest

from app.main import health, start_session
from app.schemas import Credentials


class SmokeTests(unittest.TestCase):
    def test_health_route(self) -> None:
        response = asyncio.run(health())
        self.assertEqual(response['status'], 'healthy')

    def test_start_session_returns_access_token(self) -> None:
        payload = Credentials(username='smoke_user_for_start_session_test', password='secret123')
        body = asyncio.run(start_session(payload))
        self.assertTrue(body['success'])
        self.assertIsInstance(body.get('access_token'), str)
        self.assertEqual(body.get('token_type'), 'bearer')


if __name__ == '__main__':
    unittest.main()
