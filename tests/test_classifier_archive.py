from karton.core import Resource, Task
from karton.core.test import KartonTestCase, ConfigMock, KartonBackendMock
from karton.classifier import Classifier
from .mock_helper import mock_classifier
from unittest.mock import ANY, MagicMock


class TestClassifier(KartonTestCase):
    def setUp(self):
        self.config = ConfigMock()
        self.backend = KartonBackendMock()

    def test_process_archive_7z(self):
        magic = ", ".join(
            [
                "7-zip archive data",
                "version 0.4",
            ]
        )
        self.karton = mock_classifier(magic, "application/x-7z-compressed")

        resource = Resource("file.7z", b"feeddecaf\n", sha256="sha256")
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
                "kind": "archive",
                "mime": "application/x-7z-compressed",
                "extension": "7z",
            },
            payload={
                "sample": resource,
                "tags": ["archive:7z"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_ace(self):
        magic = ", ".join(
            [
                "ACE archive data version 20",
                "from Win/32",
                "version 20 to extract",
                "contains AV-String (unregistered)",
                "solid",
            ]
        )
        self.karton = mock_classifier(magic, "application/octet-stream")

        resource = Resource("file.ace", b"feeddecaf\n", sha256="sha256")
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
                "kind": "archive",
                "mime": "application/octet-stream",
                "extension": "ace",
            },
            payload={
                "sample": resource,
                "tags": ["archive:ace"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_bz2(self):
        magic = ", ".join(
            [
                "bzip2 compressed data",
                "block size = 900k",
            ]
        )
        self.karton = mock_classifier(magic, "application/x-bzip2")

        resource = Resource("file.bz2", b"feeddecaf\n", sha256="sha256")
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
                "kind": "archive",
                "mime": "application/x-bzip2",
                "extension": "bz2",
            },
            payload={
                "sample": resource,
                "tags": ["archive:bz2"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_cab(self):
        magic = ", ".join(
            [
                "Microsoft Cabinet archive data",
                "Windows 2000/XP setup",
                "235156 bytes",
                "1 file",
                'at 0x2c +A "RFQ and Company Profile_PDF.exe"',
                "number 1",
                "12 datablocks",
                "0x1503 compression",
            ]
        )
        self.karton = mock_classifier(magic, "application/vnd.ms-cab-compressed")

        resource = Resource("file.cab", b"feeddecaf\n", sha256="sha256")
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
                "kind": "archive",
                "mime": "application/vnd.ms-cab-compressed",
                "extension": "cab",
            },
            payload={
                "sample": resource,
                "tags": ["archive:cab"],
                "magic": magic,
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_cab_no_extension(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "Microsoft Cabinet archive data",
                    "Windows 2000/XP setup",
                    "5099 bytes",
                    "1 file",
                    'at 0x2c +A "360se.ini"',
                    "number 1",
                    "1 datablock",
                    "0x1 compression",
                ]
            ),
            "application/vnd.ms-cab-compressed",
        ]
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
                "stage": "recognized",
                "origin": "karton.classifier",
                "quality": "high",
                "kind": "archive",
                "mime": "application/vnd.ms-cab-compressed",
                "extension": "cab",
            },
            payload={
                "sample": resource,
                "tags": ["archive:cab"],
                "magic": ", ".join(
                    [
                        "Microsoft Cabinet archive data",
                        "Windows 2000/XP setup",
                        "5099 bytes",
                        "1 file",
                        'at 0x2c +A "360se.ini"',
                        "number 1",
                        "1 datablock",
                        "0x1 compression",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_gz(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "gzip compressed data",
                    'was "Order 002_PDF.exe"',
                    "last modified: Thu Apr 30 23:25:26 2020",
                    "from FAT filesystem (MS-DOS",
                    "OS/2",
                    "NT)",
                ]
            ),
            "application/gzip",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.gz", b"feeddecaf\n", sha256="sha256")
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
                "kind": "archive",
                "mime": "application/gzip",
                "extension": "gz",
            },
            payload={
                "sample": resource,
                "tags": ["archive:gz"],
                "magic": ", ".join(
                    [
                        "gzip compressed data",
                        'was "Order 002_PDF.exe"',
                        "last modified: Thu Apr 30 23:25:26 2020",
                        "from FAT filesystem (MS-DOS",
                        "OS/2",
                        "NT)",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_iso(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "ISO 9660 CD-ROM filesystem data "
                    + "'DHL Shipping Document (Please Si'",
                ]
            ),
            "application/x-iso9660-image",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.iso", b"feeddecaf\n", sha256="sha256")
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
                "kind": "archive",
                "mime": "application/x-iso9660-image",
                "extension": "iso",
            },
            payload={
                "sample": resource,
                "tags": ["archive:iso"],
                "magic": ", ".join(
                    [
                        "ISO 9660 CD-ROM filesystem data "
                        + "'DHL Shipping Document (Please Si'",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_lz(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "lzip compressed data",
                    "version: 1",
                ]
            ),
            "application/x-lzip",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.lz", b"feeddecaf\n", sha256="sha256")
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
                "kind": "archive",
                "mime": "application/x-lzip",
                "extension": "lz",
            },
            payload={
                "sample": resource,
                "tags": ["archive:lz"],
                "magic": ", ".join(
                    [
                        "lzip compressed data",
                        "version: 1",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_rar(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "RAR archive data",
                    "v5",
                ]
            ),
            "application/x-rar",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.lz", b"feeddecaf\n", sha256="sha256")
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
                "kind": "archive",
                "mime": "application/x-rar",
                "extension": "rar",
            },
            payload={
                "sample": resource,
                "tags": ["archive:rar"],
                "magic": ", ".join(
                    [
                        "RAR archive data",
                        "v5",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_tar(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "POSIX tar archive",
                ]
            ),
            "application/x-tar",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.tar", b"feeddecaf\n", sha256="sha256")
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
                "kind": "archive",
                "mime": "application/x-tar",
                "extension": "tar",
            },
            payload={
                "sample": resource,
                "tags": ["archive:tar"],
                "magic": ", ".join(
                    [
                        "POSIX tar archive",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_udf(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "UDF filesystem data (version 1.5) '06_25_2020'",
                ]
            ),
            "application/x-iso9660-image",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.udf", b"feeddecaf\n", sha256="sha256")
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
                "kind": "archive",
                "mime": "application/x-iso9660-image",
                "extension": "udf",
            },
            payload={
                "sample": resource,
                "tags": ["archive:udf"],
                "magic": ", ".join(
                    [
                        "UDF filesystem data (version 1.5) '06_25_2020'",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_xz(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "XZ compressed data",
                ]
            ),
            "application/x-xz",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.xz", b"feeddecaf\n", sha256="sha256")
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
                "kind": "archive",
                "mime": "application/x-xz",
                "extension": "xz",
            },
            payload={
                "sample": resource,
                "tags": ["archive:xz"],
                "magic": ", ".join(
                    [
                        "XZ compressed data",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_archive_zip(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "Zip archive data",
                    "at least v2.0 to extract",
                ]
            ),
            "application/zip",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.zip", b"feeddecaf\n", sha256="sha256")
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
                "kind": "archive",
                "mime": "application/zip",
                "extension": "zip",
            },
            payload={
                "sample": resource,
                "tags": ["archive:zip"],
                "magic": ", ".join(["Zip archive data", "at least v2.0 to extract"]),
            },
        )
        self.assertTasksEqual(res, [expected])
