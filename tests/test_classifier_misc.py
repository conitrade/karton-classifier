from karton.classifier.classifier import Classifier
import unittest
from unittest.mock import ANY, MagicMock

from karton.core import Resource, Task
from karton.core.test import KartonTestCase, ConfigMock, KartonBackendMock
from karton.classifier import Classifier
from .mock_helper import mock_classifier, mock_resource, mock_task


class TestClassifier(KartonTestCase):
    def setUp(self):
        self.config = ConfigMock()
        self.backend = KartonBackendMock()

    def test_process_misc_ascii(self):
        magic, mime = "ASCII text...", "text/plain"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.txt")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "ascii",
                "mime": mime,
            },
            payload={
                "sample": resource,
                "tags": ["misc:ascii"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_misc_html(self):
        magic, mime = "HTML document...", "text/html"
        self.karton = mock_classifier(magic, mime)
        resource = mock_resource("file.html")
        res = self.run_task(mock_task(resource))

        expected = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "html",
                "mime": mime,
            },
            payload={
                "sample": resource,
                "tags": ["misc:html"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])
