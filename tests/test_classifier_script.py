from karton.classifier.classifier import Classifier
import unittest
from unittest.mock import ANY, MagicMock

from karton.core import Resource, Task
from karton.core.test import KartonTestCase, ConfigMock, KartonBackendMock
from karton.classifier import Classifier


class TestClassifier(KartonTestCase):
    def setUp(self):
        self.config = ConfigMock()
        self.backend = KartonBackendMock()

    def test_process_script_win32_js(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "ASCII text",
                    "with very long lines",
                    "with CRLF line terminators",
                ]
            ),
            "text/plain",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.js", b"feeddecaf\n", sha256="sha256")
        task = Task(
            {
                "type": "sample",
                "kind": "raw",
            }
        )
        task.add_payload("sample", resource)

        res = self.run_task(task)

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "script",
                "mime": "text/plain",
                "extension": "js",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["script:win32:js"],
                "magic": ", ".join(
                    [
                        "ASCII text",
                        "with very long lines",
                        "with CRLF line terminators",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_script_win32_jse(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "data",
                ]
            ),
            "application/octet-stream",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.jse", b"feeddecaf\n", sha256="sha256")
        task = Task(
            {
                "type": "sample",
                "kind": "raw",
            }
        )
        task.add_payload("sample", resource)

        res = self.run_task(task)

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "script",
                "mime": "application/octet-stream",
                "extension": "jse",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["script:win32:jse"],
                "magic": ", ".join(
                    [
                        "data",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_script_win32_ps1(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "ASCII text",
                    "with very long lines",
                ]
            ),
            "text/plain",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.ps1", b"feeddecaf\n", sha256="sha256")
        task = Task(
            {
                "type": "sample",
                "kind": "raw",
            }
        )
        task.add_payload("sample", resource)

        res = self.run_task(task)

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "script",
                "mime": "text/plain",
                "extension": "ps1",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["script:win32:ps1"],
                "magic": ", ".join(
                    [
                        "ASCII text",
                        "with very long lines",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_script_win32_vbs(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "ASCII text",
                    "with very long lines",
                    "with no line terminators",
                ]
            ),
            "text/plain",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.vbs", b"feeddecaf\n", sha256="sha256")
        task = Task(
            {
                "type": "sample",
                "kind": "raw",
            }
        )
        task.add_payload("sample", resource)

        res = self.run_task(task)

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "script",
                "mime": "text/plain",
                "extension": "vbs",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["script:win32:vbs"],
                "magic": ", ".join(
                    [
                        "ASCII text",
                        "with very long lines",
                        "with no line terminators",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])
