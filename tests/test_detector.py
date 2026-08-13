import os
import sys
import unittest
from datetime import datetime, timedelta


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

SRC_PATH = os.path.join(
    PROJECT_ROOT,
    "src"
)

sys.path.insert(
    0,
    SRC_PATH
)


from detector import (
    calculate_risk,
    detect_success_after_failures,
    detect_brute_force_attempts,
    detect_password_spraying,
    detect_credential_stuffing,
    detect_multiple_account_targeting,
    detect_anomalous_login_bursts
)


class TestDetector(unittest.TestCase):

    def setUp(self):
        self.base_time = datetime(
            2026,
            7,
            5,
            10,
            0,
            0
        )

    def create_log(
        self,
        event_type,
        user,
        ip,
        seconds
    ):
        return {
            "event_type": event_type,
            "user": user,
            "ip": ip,
            "timestamp": (
                self.base_time
                + timedelta(seconds=seconds)
            ),
            "raw_log": ""
        }

    def test_calculate_risk(self):
        self.assertEqual(
            calculate_risk(2),
            "LOW"
        )

        self.assertEqual(
            calculate_risk(3),
            "MEDIUM"
        )

        self.assertEqual(
            calculate_risk(5),
            "HIGH"
        )

    def test_success_after_failures_detection(self):
        logs = [
            self.create_log(
                "FAILED",
                "admin",
                "192.168.1.20",
                0
            ),
            self.create_log(
                "FAILED",
                "admin",
                "192.168.1.20",
                10
            ),
            self.create_log(
                "FAILED",
                "admin",
                "192.168.1.20",
                20
            ),
            self.create_log(
                "SUCCESS",
                "admin",
                "192.168.1.20",
                30
            )
        ]

        alerts = detect_success_after_failures(
            logs
        )

        self.assertEqual(
            len(alerts),
            1
        )

        self.assertEqual(
            alerts[0]["type"],
            "SUCCESS_AFTER_FAILURES"
        )

        self.assertEqual(
            alerts[0]["ip"],
            "192.168.1.20"
        )

        self.assertEqual(
            alerts[0]["user"],
            "admin"
        )

        self.assertEqual(
            alerts[0]["severity"],
            "HIGH"
        )

    def test_brute_force_detection(self):
        logs = [
            self.create_log(
                "FAILED",
                "root",
                "172.16.0.8",
                0
            ),
            self.create_log(
                "FAILED",
                "root",
                "172.16.0.8",
                10
            ),
            self.create_log(
                "FAILED",
                "root",
                "172.16.0.8",
                20
            ),
            self.create_log(
                "FAILED",
                "root",
                "172.16.0.8",
                30
            ),
            self.create_log(
                "FAILED",
                "root",
                "172.16.0.8",
                40
            )
        ]

        alerts = detect_brute_force_attempts(
            logs
        )

        self.assertEqual(
            len(alerts),
            1
        )

        self.assertEqual(
            alerts[0]["type"],
            "BRUTE_FORCE"
        )

        self.assertEqual(
            alerts[0]["attempts"],
            5
        )

        self.assertEqual(
            alerts[0]["severity"],
            "HIGH"
        )

    def test_password_spraying_detection(self):
        logs = [
            self.create_log(
                "FAILED",
                "alice",
                "10.10.10.50",
                0
            ),
            self.create_log(
                "FAILED",
                "bob",
                "10.10.10.50",
                10
            ),
            self.create_log(
                "FAILED",
                "carol",
                "10.10.10.50",
                20
            ),
            self.create_log(
                "FAILED",
                "admin",
                "10.10.10.50",
                30
            )
        ]

        alerts = detect_password_spraying(
            logs
        )

        self.assertEqual(
            len(alerts),
            1
        )

        self.assertEqual(
            alerts[0]["type"],
            "PASSWORD_SPRAYING"
        )

        self.assertEqual(
            alerts[0]["user_count"],
            4
        )

        self.assertEqual(
            alerts[0]["severity"],
            "HIGH"
        )

    def test_credential_stuffing_detection(self):
        logs = [
            self.create_log(
                "FAILED",
                "alice",
                "203.0.113.50",
                0
            ),
            self.create_log(
                "FAILED",
                "bob",
                "203.0.113.50",
                10
            ),
            self.create_log(
                "FAILED",
                "carol",
                "203.0.113.50",
                20
            ),
            self.create_log(
                "FAILED",
                "alice",
                "203.0.113.50",
                30
            ),
            self.create_log(
                "FAILED",
                "bob",
                "203.0.113.50",
                40
            ),
            self.create_log(
                "SUCCESS",
                "bob",
                "203.0.113.50",
                50
            )
        ]

        alerts = detect_credential_stuffing(
            logs
        )

        self.assertEqual(
            len(alerts),
            1
        )

        self.assertEqual(
            alerts[0]["type"],
            "CREDENTIAL_STUFFING"
        )

        self.assertEqual(
            alerts[0]["failed_attempts"],
            5
        )

        self.assertEqual(
            alerts[0]["successful_logins"],
            1
        )

        self.assertEqual(
            alerts[0]["user_count"],
            3
        )

    def test_multiple_account_targeting_detection(self):
        logs = [
            self.create_log(
                "FAILED",
                "alice",
                "198.51.100.25",
                0
            ),
            self.create_log(
                "FAILED",
                "bob",
                "198.51.100.25",
                10
            ),
            self.create_log(
                "FAILED",
                "carol",
                "198.51.100.25",
                20
            )
        ]

        alerts = detect_multiple_account_targeting(
            logs
        )

        self.assertEqual(
            len(alerts),
            1
        )

        self.assertEqual(
            alerts[0]["type"],
            "MULTI_ACCOUNT_TARGETING"
        )

        self.assertEqual(
            alerts[0]["user_count"],
            3
        )

    def test_anomalous_login_burst_detection(self):
        logs = [
            self.create_log(
                "FAILED",
                "alice",
                "192.0.2.10",
                0
            ),
            self.create_log(
                "FAILED",
                "alice",
                "192.0.2.10",
                10
            ),
            self.create_log(
                "FAILED",
                "bob",
                "192.0.2.10",
                20
            ),
            self.create_log(
                "FAILED",
                "bob",
                "192.0.2.10",
                30
            ),
            self.create_log(
                "SUCCESS",
                "carol",
                "192.0.2.10",
                40
            )
        ]

        alerts = detect_anomalous_login_bursts(
            logs
        )

        self.assertEqual(
            len(alerts),
            1
        )

        self.assertEqual(
            alerts[0]["type"],
            "ANOMALOUS_LOGIN_BURST"
        )

        self.assertEqual(
            alerts[0]["events"],
            5
        )

        self.assertEqual(
            alerts[0]["failed_attempts"],
            4
        )

        self.assertEqual(
            alerts[0]["successful_logins"],
            1
        )


if __name__ == "__main__":
    unittest.main()