from karton.core import Resource, Task
from karton.core.test import KartonTestCase, ConfigMock, KartonBackendMock
from karton.classifier.classifier import Classifier
from unittest.mock import ANY, MagicMock
from typing import Tuple


def mock_classifier(magic: str, mime: str) -> Classifier:
    m = MagicMock()
    m.side_effect = [
        magic,
        mime,
    ]
    return Classifier(magic=m, config=ConfigMock(), backend=KartonBackendMock())


def mock_resource(filename: str) -> Resource:
    return Resource(filename, b"feeddecaf\n", sha256="sha256")


def mock_task(resource: Resource) -> Task:
    task = Task(
        {
            "type": "sample",
            "kind": "raw",
        }
    )
    task.add_payload("sample", resource)
    return task
