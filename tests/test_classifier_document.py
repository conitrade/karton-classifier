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

    def test_process_document_doc(self):
        m = MagicMock()
        m.side_effect = [
            ', '.join([
                'Composite Document File V2 Document',
                'Little Endian',
                'Os: Windows',
                'Version 6.1',
                'Code page: 1251',
                'Title:    ',
                'Template: Normal',
                'Last Saved By: Z',
                'Revision Number: 5',
                'Name of Creating Application: Microsoft Office Word',
                'Total Editing Time: 01:33:00',
                'Last Printed: Sat Nov  5 19:25:00 2016',
                'Create Time/Date: Sun Oct 30 16:29:00 2016',
                'Last Saved Time/Date: Sat Nov  5 19:28:00 2016',
                'Number of Pages: 9',
                'Number of Words: 1800',
                'Number of Characters: 10264',
                'Security: 0'
            ]),
            'application/msword',
        ]
        self.karton = Classifier(
            magic=m, config=self.config, backend=self.backend
        )

        resource = Resource('file.doc', b'feeddecaf\n', sha256='sha256')
        task = Task({
            'type': 'sample',
            'kind': 'raw',
        })
        task.add_payload('sample', resource)

        res = self.run_task(task)

        expected = Task(
            headers={
                'type': 'sample',
                'stage': 'recognized',
                'origin': 'karton.classifier',
                'quality': 'high',
                'kind': 'document',
                'mime': 'application/msword',
                'extension': 'doc',
                'platform': 'win32',

            },
            payload={
                'sample': resource,
                'tags': ['document:win32:doc'],
                'magic': ', '.join([
                    'Composite Document File V2 Document',
                    'Little Endian',
                    'Os: Windows',
                    'Version 6.1',
                    'Code page: 1251',
                    'Title:    ',
                    'Template: Normal',
                    'Last Saved By: Z',
                    'Revision Number: 5',
                    'Name of Creating Application: Microsoft Office Word',
                    'Total Editing Time: 01:33:00',
                    'Last Printed: Sat Nov  5 19:25:00 2016',
                    'Create Time/Date: Sun Oct 30 16:29:00 2016',
                    'Last Saved Time/Date: Sat Nov  5 19:28:00 2016',
                    'Number of Pages: 9',
                    'Number of Words: 1800',
                    'Number of Characters: 10264',
                    'Security: 0'
                ]),
            }
        )
        self.assertTasksEqual(res, [expected])

    def test_process_document_docx(self):
        m = MagicMock()
        m.side_effect = [
            ', '.join([
                'Microsoft Word 2007+',
            ]),
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        ]
        self.karton = Classifier(
            magic=m, config=self.config, backend=self.backend
        )

        resource = Resource('file.docx', b'feeddecaf\n', sha256='sha256')
        task = Task({
            'type': 'sample',
            'kind': 'raw',
        })
        task.add_payload('sample', resource)

        res = self.run_task(task)

        expected = Task(
            headers={
                'type': 'sample',
                'stage': 'recognized',
                'origin': 'karton.classifier',
                'quality': 'high',
                'kind': 'document',
                'mime': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'extension': 'docx',
                'platform': 'win32',

            },
            payload={
                'sample': resource,
                'tags': ['document:win32:docx'],
                'magic': ', '.join([
                    'Microsoft Word 2007+',
                ]),
            }
        )
        self.assertTasksEqual(res, [expected])

    def test_process_document_pdf(self):
        m = MagicMock()
        m.side_effect = [
            ', '.join([
                'PDF document',
                'version 1.4',
            ]),
            'application/pdf',
        ]
        self.karton = Classifier(
            magic=m, config=self.config, backend=self.backend
        )

        resource = Resource('file.pdf', b'feeddecaf\n', sha256='sha256')
        task = Task({
            'type': 'sample',
            'kind': 'raw',
        })
        task.add_payload('sample', resource)

        res = self.run_task(task)

        expected = Task(
            headers={
                'type': 'sample',
                'stage': 'recognized',
                'origin': 'karton.classifier',
                'quality': 'high',
                'kind': 'document',
                'mime': 'application/pdf',
                'extension': 'pdf',
                'platform': 'win32',

            },
            payload={
                'sample': resource,
                'tags': ['document:win32:pdf'],
                'magic': ', '.join([
                    'PDF document',
                    'version 1.4',
                ]),
            }
        )
        self.assertTasksEqual(res, [expected])

    def test_process_document_rtf(self):
        m = MagicMock()
        m.side_effect = [
            ', '.join([
                'Rich Text Format data',
                'version 1',
                'unknown character set',
            ]),
            'text/rtf',
        ]
        self.karton = Classifier(
            magic=m, config=self.config, backend=self.backend
        )

        resource = Resource('file.rtf', b'feeddecaf\n', sha256='sha256')
        task = Task({
            'type': 'sample',
            'kind': 'raw',
        })
        task.add_payload('sample', resource)

        res = self.run_task(task)

        expected = Task(
            headers={
                'type': 'sample',
                'stage': 'recognized',
                'origin': 'karton.classifier',
                'quality': 'high',
                'kind': 'document',
                'mime': 'text/rtf',
                'extension': 'rtf',
                'platform': 'win32',

            },
            payload={
                'sample': resource,
                'tags': ['document:win32:rtf'],
                'magic': ', '.join([
                    'Rich Text Format data',
                    'version 1',
                    'unknown character set',
                ]),
            }
        )
        self.assertTasksEqual(res, [expected])

    def test_process_document_xls(self):
        m = MagicMock()
        m.side_effect = [
            ', '.join([
                'Composite Document File V2 Document',
                'Little Endian',
                'Os: Windows',
                'Version 6.2',
                'Code page: 1252',
                'Name of Creating Application: Microsoft Excel',
                'Create Time/Date: Thu Mar 19 21:34:27 2020',
                'Last Saved Time/Date: Thu Mar 19 21:47:49 2020',
                'Security: 0',
            ]),
            'application/vnd.ms-excel',
        ]
        self.karton = Classifier(
            magic=m, config=self.config, backend=self.backend
        )

        resource = Resource('file.xls', b'feeddecaf\n', sha256='sha256')
        task = Task({
            'type': 'sample',
            'kind': 'raw',
        })
        task.add_payload('sample', resource)

        res = self.run_task(task)

        expected = Task(
            headers={
                'type': 'sample',
                'stage': 'recognized',
                'origin': 'karton.classifier',
                'quality': 'high',
                'kind': 'document',
                'mime': 'application/vnd.ms-excel',
                'extension': 'xls',
                'platform': 'win32',

            },
            payload={
                'sample': resource,
                'tags': ['document:win32:xls'],
                'magic': ', '.join([
                    'Composite Document File V2 Document',
                    'Little Endian',
                    'Os: Windows',
                    'Version 6.2',
                    'Code page: 1252',
                    'Name of Creating Application: Microsoft Excel',
                    'Create Time/Date: Thu Mar 19 21:34:27 2020',
                    'Last Saved Time/Date: Thu Mar 19 21:47:49 2020',
                    'Security: 0',
                ]),
            }
        )
        self.assertTasksEqual(res, [expected])

    def test_process_document_xlsx(self):
        m = MagicMock()
        m.side_effect = [
            ', '.join([
                'Microsoft Excel 2007+',
            ]),
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        ]
        self.karton = Classifier(
            magic=m, config=self.config, backend=self.backend
        )

        resource = Resource('file.xlsx', b'feeddecaf\n', sha256='sha256')
        task = Task({
            'type': 'sample',
            'kind': 'raw',
        })
        task.add_payload('sample', resource)

        res = self.run_task(task)

        expected = Task(
            headers={
                'type': 'sample',
                'stage': 'recognized',
                'origin': 'karton.classifier',
                'quality': 'high',
                'kind': 'document',
                'mime': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'extension': 'xlsx',
                'platform': 'win32',

            },
            payload={
                'sample': resource,
                'tags': ['document:win32:xlsx'],
                'magic': ', '.join([
                    'Microsoft Excel 2007+',
                ]),
            }
        )
        self.assertTasksEqual(res, [expected])
