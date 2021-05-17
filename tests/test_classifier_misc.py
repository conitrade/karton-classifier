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

    def test_process_misc_ascii(self):
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

        resource = Resource("file.txt", b"feeddecaf\n", sha256="sha256")
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
                "kind": "ascii",
                "mime": "text/plain",
            },
            payload={
                "sample": resource,
                "tags": ["misc:ascii"],
                "magic": ", ".join(
                    ["ASCII text", "with very long lines", "with no line terminators"]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_misc_html(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "HTML document",
                    "ASCII text",
                ]
            ),
            "text/html",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.html", b"feeddecaf\n", sha256="sha256")
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
                "kind": "html",
                "mime": "text/html",
            },
            payload={
                "sample": resource,
                "tags": ["misc:html"],
                "magic": ", ".join(
                    [
                        "HTML document",
                        "ASCII text",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])
