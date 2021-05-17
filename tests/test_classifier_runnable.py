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

    def test_process_runnable_android_dec(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "Dalvik dex file version 035",
                ]
            ),
            "application/octet-stream",
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
                "kind": "runnable",
                "mime": "application/octet-stream",
                "extension": "dex",
                "platform": "android",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:android:dex"],
                "magic": ", ".join(
                    [
                        "Dalvik dex file version 035",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_linux(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "ELF 32-bit MSB executable",
                    "SPARC",
                    "version 1 (SYSV)",
                ]
            ),
            "application/x-executable",
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
                "kind": "runnable",
                "mime": "application/x-executable",
                "platform": "linux",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:linux"],
                "magic": ", ".join(
                    [
                        "ELF 32-bit MSB executable",
                        "SPARC",
                        "version 1 (SYSV)",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win32_dll(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "PE32 executable (DLL) (console) Intel 80386",
                    "for MS Windows",
                ]
            ),
            "application/x-dosexec",
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
                "kind": "runnable",
                "mime": "application/x-dosexec",
                "extension": "dll",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win32:dll"],
                "magic": ", ".join(
                    [
                        "PE32 executable (DLL) (console) Intel 80386",
                        "for MS Windows",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win32_exe(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "PE32 executable (GUI) Intel 80386 Mono/.Net assembly",
                    "for MS Windows",
                ]
            ),
            "application/x-dosexec",
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
                "kind": "runnable",
                "mime": "application/x-dosexec",
                "extension": "exe",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win32:exe"],
                "magic": ", ".join(
                    [
                        "PE32 executable (GUI) Intel 80386 Mono/.Net assembly",
                        "for MS Windows",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win32_jar(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "Zip archive data",
                    "at least v1.0 to extract",
                ]
            ),
            "application/zip",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.jar", b"feeddecaf\n", sha256="sha256")
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
                "kind": "runnable",
                "mime": "application/zip",
                "extension": "jar",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win32:jar"],
                "magic": ", ".join(
                    [
                        "Zip archive data",
                        "at least v1.0 to extract",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win32_lnk(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "MS Windows shortcut",
                    "Item id list present",
                    "Has Description string",
                    "Has Relative path",
                    "Has Working directory",
                    "Has command line arguments",
                    "Icon number=67",
                    "ctime=Mon Jan  1 00:00:00 1601",
                    "mtime=Mon Jan  1 00:00:00 1601",
                    "atime=Mon Jan  1 00:00:00 1601",
                    "length=0",
                    "window=hidenormalshowminimized",
                ]
            ),
            "application/octet-stream",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.lnk", b"feeddecaf\n", sha256="sha256")
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
                "kind": "runnable",
                "mime": "application/octet-stream",
                "extension": "lnk",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win32:lnk"],
                "magic": ", ".join(
                    [
                        "MS Windows shortcut",
                        "Item id list present",
                        "Has Description string",
                        "Has Relative path",
                        "Has Working directory",
                        "Has command line arguments",
                        "Icon number=67",
                        "ctime=Mon Jan  1 00:00:00 1601",
                        "mtime=Mon Jan  1 00:00:00 1601",
                        "atime=Mon Jan  1 00:00:00 1601",
                        "length=0",
                        "window=hidenormalshowminimized",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win32_msi(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "Composite Document File V2 Document",
                    "Little Endian",
                    "Os: Windows",
                    "Version 6.1",
                    "MSI Installer",
                    "Code page: 1252",
                    "Last Printed: Fri Sep 21 09:56:09 2012",
                    "Create Time/Date: Fri Sep 21 09:56:09 2012",
                    "Name of Creating Application: Windows Installer",
                    "Title: Exe to msi converter free",
                    "Author: www.exetomsi.com",
                    "Template: ;0",
                    "Last Saved By: devuser",
                    "Revision Number: {C35CF0AA-9B3F-4903-9F05-EBF606D58D3E}",
                    "Last Saved Time/Date: Tue May 21 11:56:44 2013",
                    "Number of Pages: 100",
                    "Number of Words: 0",
                    "Security: 0",
                ]
            ),
            "application/x-msi",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.jar", b"feeddecaf\n", sha256="sha256")
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
                "kind": "runnable",
                "mime": "application/x-msi",
                "extension": "msi",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win32:msi"],
                "magic": ", ".join(
                    [
                        "Composite Document File V2 Document",
                        "Little Endian",
                        "Os: Windows",
                        "Version 6.1",
                        "MSI Installer",
                        "Code page: 1252",
                        "Last Printed: Fri Sep 21 09:56:09 2012",
                        "Create Time/Date: Fri Sep 21 09:56:09 2012",
                        "Name of Creating Application: Windows Installer",
                        "Title: Exe to msi converter free",
                        "Author: www.exetomsi.com",
                        "Template: ;0",
                        "Last Saved By: devuser",
                        "Revision Number: {C35CF0AA-9B3F-4903-9F05-EBF606D58D3E}",
                        "Last Saved Time/Date: Tue May 21 11:56:44 2013",
                        "Number of Pages: 100",
                        "Number of Words: 0",
                        "Security: 0",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win32_swf(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "Macromedia Flash data (compressed)",
                    "version 36",
                ]
            ),
            "application/x-shockwave-flash",
        ]
        self.karton = Classifier(magic=m, config=self.config, backend=self.backend)

        resource = Resource("file.swf", b"feeddecaf\n", sha256="sha256")
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
                "kind": "runnable",
                "mime": "application/x-shockwave-flash",
                "extension": "swf",
                "platform": "win32",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win32:swf"],
                "magic": ", ".join(
                    [
                        "Macromedia Flash data (compressed)",
                        "version 36",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win64_dll(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(["PE32+ executable (DLL) (GUI) x86-64", "for MS Windows"]),
            "application/x-dosexec",
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
                "kind": "runnable",
                "mime": "application/x-dosexec",
                "extension": "dll",
                "platform": "win64",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win64:dll"],
                "magic": ", ".join(
                    [
                        "PE32+ executable (DLL) (GUI) x86-64",
                        "for MS Windows",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])

    def test_process_runnable_win64_exe(self):
        m = MagicMock()
        m.side_effect = [
            ", ".join(
                [
                    "PE32+ executable (console) x86-64",
                    "for MS Windows",
                ]
            ),
            "application/x-dosexec",
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
                "kind": "runnable",
                "mime": "application/x-dosexec",
                "extension": "exe",
                "platform": "win64",
            },
            payload={
                "sample": resource,
                "tags": ["runnable:win64:exe"],
                "magic": ", ".join(
                    [
                        "PE32+ executable (console) x86-64",
                        "for MS Windows",
                    ]
                ),
            },
        )
        self.assertTasksEqual(res, [expected])
