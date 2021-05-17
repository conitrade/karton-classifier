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

    def test_process(self):
        m = MagicMock()
        m.side_effect = ["ASCII text", "text/plain"]
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
                "magic": "ASCII text",
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_unknown(self):
        m = MagicMock()
        m.side_effect = ["", None]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file", b"feeddecaf\n", sha256="sha256")
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
                "stage": "unrecognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "unknown",
            },
            payload={
                "sample": resource,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_error(self):
        m = MagicMock()
        m.side_effect = Exception("unknown error")
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
                "stage": "unrecognized",
                "origin": "karton.classifier",
                "kind": "unknown",
                "quality": "high",
            },
            payload={
                "sample": resource,
            },
        )
        self.assertTasksEqual(res, [expected])
