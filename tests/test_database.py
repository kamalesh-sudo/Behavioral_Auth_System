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
        self.assertEqual(created['role'], 'user')

        verified = self.db.verify_user('alice', 'secret123')
        self.assertTrue(verified['success'])
        self.assertEqual(verified['username'], 'alice')
        self.assertEqual(verified['role'], 'user')

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

    def test_set_user_role_and_security_events(self) -> None:
        created = self.db.create_user('erin', 'secret123')
        self.assertTrue(created['success'])

        updated = self.db.set_user_role('erin', 'analyst')
        self.assertTrue(updated['success'])
        self.assertEqual(updated['role'], 'analyst')

        event = self.db.log_security_event(
            username='erin',
            event_type='TEST_EVENT',
            reason='unit test event',
            session_id='session-4',
            risk_score=0.2,
        )
        self.assertTrue(event['success'])

        events = self.db.get_security_events(limit=10, username='erin')
        self.assertTrue(events['success'])
        self.assertEqual(events['events'][0]['event_type'], 'TEST_EVENT')

    def test_ip_and_device_block_controls(self) -> None:
        ip = "203.0.113.10"
        fp = "device-fingerprint-alpha"

        self.assertFalse(self.db.is_ip_blocked(ip))
        blocked_ip = self.db.block_ip(ip, "test block", blocked_by="unit-test", duration_minutes=30)
        self.assertTrue(blocked_ip["success"])
        self.assertTrue(self.db.is_ip_blocked(ip))

        self.assertFalse(self.db.is_device_fingerprint_blocked(fp))
        blocked_device = self.db.block_device_fingerprint(fp, "test block", blocked_by="unit-test")
        self.assertTrue(blocked_device["success"])
        self.assertTrue(self.db.is_device_fingerprint_blocked(fp))

        blocked_ips = self.db.list_blocked_ips(limit=20)
        self.assertTrue(blocked_ips["success"])
        self.assertTrue(any(item["ip_address"] == ip for item in blocked_ips["blocked_ips"]))

        blocked_devices = self.db.list_blocked_devices(limit=20)
        self.assertTrue(blocked_devices["success"])
        self.assertGreaterEqual(len(blocked_devices["blocked_devices"]), 1)

        unblocked_ip = self.db.unblock_ip(ip)
        self.assertTrue(unblocked_ip["success"])
        self.assertFalse(self.db.is_ip_blocked(ip))

        unblocked_device = self.db.unblock_device_fingerprint(fp)
        self.assertTrue(unblocked_device["success"])
        self.assertFalse(self.db.is_device_fingerprint_blocked(fp))

    def test_register_and_lookup_known_user_device(self) -> None:
        created = self.db.create_user('gina', 'secret123')
        self.assertTrue(created['success'])
        fp = "device-fingerprint-beta"

        self.assertFalse(self.db.is_known_user_device(created['user_id'], fp))
        registered = self.db.register_user_device(created['user_id'], fp, ip_address="198.51.100.20")
        self.assertTrue(registered["success"])
        self.assertTrue(self.db.is_known_user_device(created['user_id'], fp))

    def test_project_and_task_flow(self) -> None:
        owner = self.db.create_user('frank', 'secret123')
        self.assertTrue(owner['success'])

        project = self.db.create_project(owner['user_id'], 'Client Portal', 'Freelance project')
        self.assertTrue(project['success'])

        created_task = self.db.create_task(
            project_id=project['project_id'],
            title='Build login screen',
            description='Implement auth UX',
            status='todo',
            priority='high',
            assignee_id=owner['user_id'],
            due_date='2026-03-01',
            created_by=owner['user_id'],
        )
        self.assertTrue(created_task['success'])

        tasks = self.db.get_tasks_for_project(project['project_id'])
        self.assertTrue(tasks['success'])
        self.assertEqual(len(tasks['tasks']), 1)
        self.assertEqual(tasks['tasks'][0]['title'], 'Build login screen')

        updated = self.db.update_task(created_task['task_id'], status='in_progress')
        self.assertTrue(updated['success'])

        task = self.db.get_task(created_task['task_id'])
        self.assertTrue(task['success'])
        self.assertEqual(task['task']['status'], 'in_progress')


if __name__ == '__main__':
    unittest.main()
