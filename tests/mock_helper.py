from karton.core.test import KartonTestCase, ConfigMock, KartonBackendMock
from karton.classifier.classifier import Classifier
from unittest.mock import ANY, MagicMock


def mock_classifier(magic: str, mime: str):
    m = MagicMock()
    m.side_effect = [
        magic,
        mime,
    ]
    return Classifier(magic=m, config=ConfigMock(), backend=KartonBackendMock())
