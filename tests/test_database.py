import tempfile
import unittest
from pathlib import Path

from app.database import AuthDatabase


class AuthDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / 'users.db')
        self.db = AuthDatabase(self.db_path)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_create_and_verify_user(self) -> None:
        created = self.db.create_user('alice', 'secret123')
        self.assertTrue(created['success'])

        verified = self.db.verify_user('alice', 'secret123')
        self.assertTrue(verified['success'])
        self.assertEqual(verified['username'], 'alice')

    def test_block_user_disables_login_and_marks_blocked(self) -> None:
        created = self.db.create_user('bob', 'secret123')
        self.assertTrue(created['success'])

        blocked = self.db.block_user('bob', 'session-1', 0.95, 'test anomaly')
        self.assertTrue(blocked['success'])

        verified = self.db.verify_user('bob', 'secret123')
        self.assertFalse(verified['success'])
        self.assertIn('disabled', verified['error'].lower())
        self.assertTrue(self.db.is_user_blocked('bob'))
        self.assertTrue(self.db.is_user_id_blocked(created['user_id']))

    def test_get_or_create_returns_block_error_for_blocked_user(self) -> None:
        created = self.db.create_user('charlie', 'secret123')
        self.assertTrue(created['success'])
        self.db.block_user('charlie', 'session-2', 0.91, 'test anomaly')

        result = self.db.get_or_create_user('charlie', 'secret123')
        self.assertFalse(result['success'])
        self.assertIn('disabled', result['error'].lower())

    def test_save_behavioral_profile_and_history(self) -> None:
        created = self.db.create_user('dana', 'secret123')
        self.assertTrue(created['success'])

        saved = self.db.save_behavioral_profile(
            user_id=created['user_id'],
            session_id='session-3',
            keystroke_data=[{'type': 'keydown', 'timestamp': 1}],
            mouse_data=[{'type': 'mousemove', 'timestamp': 2}],
            risk_score=0.3,
        )
        self.assertTrue(saved['success'])

        history = self.db.get_behavioral_history(created['user_id'], 10)
        self.assertTrue(history['success'])
        self.assertEqual(len(history['history']), 1)
        self.assertEqual(history['history'][0]['session_id'], 'session-3')


if __name__ == '__main__':
    unittest.main()
