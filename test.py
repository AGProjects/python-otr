#!/usr/bin/python

import time
import unittest

from application import log
from application.notification import IObserver, NotificationCenter
from application.python import Null
from application.python.queue import EventQueue
from threading import Event
from zope.interface import implements

from otr import OTRTransport, OTRSession, OTRState, SMPStatus
from otr.cryptography import DSAPrivateKey
from otr.exceptions import IgnoreMessage


class DataConnection(object):
    implements(IObserver)

    def __init__(self, name):
        self.name = name
        self.secret = None
        self.private_key = DSAPrivateKey.generate()
        self.otr_session = OTRSession(self.private_key, transport=self)
        self.peer = None
        self.send_queue = EventQueue(handler=self._send_handler)
        self.send_queue.start()
        self.ake_done = Event()
        self.smp_done = Event()
        self.all_done = Event()
        self.otr_done = Event()
        self.smp_status = None
        self.same_secrets = None
        self.sent_message = None
        self.received_message = None
        NotificationCenter().add_observer(self, sender=self.otr_session)

    def _send_handler(self, message):
        time.sleep(0.01)
        self.peer.receive(message)

    def connect(self, peer):
        self.peer = peer

    def disconnect(self):
        self.send_queue.stop()
        self.send_queue = None

    def start_otr(self, secret=None):
        self.secret = secret
        self.otr_session.start()

    def stop_otr(self):
        self.otr_session.stop()

    def inject_otr_message(self, message):
        log.debug("{0.name} sending: {1!r}".format(self, message))
        self.send_queue.put(message)

    def send(self, content, content_type='text/plain'):
        log.debug("{0.name} encoding: {1!r}".format(self, content))
        self.sent_message = content
        content = self.otr_session.handle_output(content, content_type)
        log.debug("{0.name} sending: {1!r}".format(self, content))
        self.send_queue.put(content)

    def receive(self, message):
        # log.debug("{0.name} received: {1!r}".format(self, message))
        try:
            message = self.otr_session.handle_input(message, 'text/plain')
        except IgnoreMessage:
            return
        else:
            log.debug("{0.name} decoded:  {1!r}".format(self, message))
            self.received_message = message
            self.all_done.set()

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_{0.name}'.format(notification), Null)
        handler(notification)

    def _NH_OTRSessionStateChanged(self, notification):
        if notification.data.new_state is OTRState.Encrypted:
            self.ake_done.set()
            if self.secret is None:
                self.smp_done.set()
            elif self.name < self.peer.name:
                self.otr_session.smp_verify(secret=self.secret)
        elif notification.data.old_state is OTRState.Encrypted:
            self.otr_done.set()

    def _NH_OTRSessionSMPVerificationDidStart(self, notification):
        if notification.data.originator == 'remote':
            if self.secret:
                self.otr_session.smp_answer(secret=self.secret)
            else:
                self.otr_session.smp_abort()

    def _NH_OTRSessionSMPVerificationDidNotStart(self, notification):
        self.smp_status = notification.data.reason
        self.smp_done.set()

    def _NH_OTRSessionSMPVerificationDidEnd(self, notification):
        self.same_secrets = notification.data.same_secrets
        self.smp_status = notification.data.status
        self.smp_done.set()

OTRTransport.register(DataConnection)


class NotificationObserver(object):
    implements(IObserver)

    def start(self):
        notification_center = NotificationCenter()
        notification_center.add_observer(self)

    def stop(self):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self)

    @staticmethod
    def handle_notification(notification):
        log.debug("--- {0.name!s} from {0.sender!r} with data: {0.data!r}".format(notification))


class OTRTest(unittest.TestCase):
    notification_observer = None

    @classmethod
    def setUpClass(cls):
        cls.notification_observer = NotificationObserver()
        cls.notification_observer.start()

    @classmethod
    def tearDownClass(cls):
        cls.notification_observer.stop()
        cls.notification_observer = None

    def setUp(self):
        self.local_endpoint = DataConnection('local')
        self.remote_endpoint = DataConnection('remote')
        self.local_endpoint.connect(self.remote_endpoint)
        self.remote_endpoint.connect(self.local_endpoint)

    def tearDown(self):
        self.local_endpoint.disconnect()
        self.remote_endpoint.disconnect()

    def test_ake_one_way(self):
        self.local_endpoint.start_otr()
        self.local_endpoint.ake_done.wait(1)
        self.remote_endpoint.ake_done.wait(1)
        self.assertIs(self.local_endpoint.otr_session.state, OTRState.Encrypted, "AKE failed on local endpoint")
        self.assertIs(self.remote_endpoint.otr_session.state, OTRState.Encrypted, "AKE failed on remote endpoint")

    def test_ake_two_way(self):
        self.local_endpoint.start_otr()
        self.remote_endpoint.start_otr()
        self.local_endpoint.ake_done.wait(1)
        self.remote_endpoint.ake_done.wait(1)
        self.assertIs(self.local_endpoint.otr_session.state, OTRState.Encrypted, "AKE failed on local endpoint")
        self.assertIs(self.remote_endpoint.otr_session.state, OTRState.Encrypted, "AKE failed on remote endpoint")

    def test_smp_same_secret(self):
        self.local_endpoint.start_otr(secret='foobar')
        self.remote_endpoint.start_otr(secret='foobar')
        self.local_endpoint.smp_done.wait(1)
        self.remote_endpoint.smp_done.wait(1)
        self.assertIs(self.local_endpoint.smp_status, SMPStatus.Success, "SMP was not successful for the local endpoint")
        self.assertIs(self.remote_endpoint.smp_status, SMPStatus.Success, "SMP was not successful for the remote endpoint")
        self.assertTrue(self.local_endpoint.same_secrets, "SMP didn't find that secrets were the same for the local endpoint")
        self.assertTrue(self.remote_endpoint.same_secrets, "SMP didn't find that secrets were the same for the remote endpoint")

    def test_smp_different_secret(self):
        self.local_endpoint.start_otr(secret='foobar')
        self.remote_endpoint.start_otr(secret='foobar2')
        self.local_endpoint.smp_done.wait(1)
        self.remote_endpoint.smp_done.wait(1)
        self.assertIs(self.local_endpoint.smp_status, SMPStatus.Success, "SMP was not successful for the local endpoint")
        self.assertIs(self.remote_endpoint.smp_status, SMPStatus.Success, "SMP was not successful for the remote endpoint")
        self.assertFalse(self.local_endpoint.same_secrets, "SMP didn't find that secrets were different for the local endpoint")
        self.assertFalse(self.remote_endpoint.same_secrets, "SMP didn't find that secrets were different for the remote endpoint")

    def test_smp_unavailable(self):
        self.local_endpoint.start_otr(secret='foobar')
        self.remote_endpoint.start_otr(secret=None)  # remote endpoint will abort the SMP as it doesn't have a secret
        self.local_endpoint.smp_done.wait(1)
        self.remote_endpoint.smp_done.wait(1)
        self.assertIs(self.local_endpoint.smp_status, SMPStatus.Interrupted, "SMP was not aborted for the local endpoint")
        self.assertIs(self.remote_endpoint.smp_status, SMPStatus.Interrupted, "SMP was not aborted for the remote endpoint")

    def test_text_encryption(self):
        self.local_endpoint.start_otr()
        self.remote_endpoint.start_otr()
        self.local_endpoint.ake_done.wait(1)
        self.remote_endpoint.ake_done.wait(1)
        self.local_endpoint.send('hello')
        self.remote_endpoint.send('test')
        self.local_endpoint.all_done.wait(1)
        self.remote_endpoint.all_done.wait(1)
        self.assertEqual(self.local_endpoint.sent_message, self.remote_endpoint.received_message, "The message sent by local was not received correctly on remote")
        self.assertEqual(self.remote_endpoint.sent_message, self.local_endpoint.received_message, "The message sent by remote was not received correctly on local")

    def test_otr_shutdown_one_way(self):
        self.local_endpoint.start_otr()
        self.remote_endpoint.start_otr()
        self.local_endpoint.ake_done.wait(1)
        self.remote_endpoint.ake_done.wait(1)
        self.local_endpoint.stop_otr()
        self.local_endpoint.otr_done.wait(1)
        self.remote_endpoint.otr_done.wait(1)
        self.assertIs(self.local_endpoint.otr_session.state, OTRState.Plaintext, "Local session state is not Plaintext")
        self.assertIs(self.remote_endpoint.otr_session.state, OTRState.Finished, "Remote session state is not Finished")
        self.remote_endpoint.stop_otr()
        self.assertIs(self.remote_endpoint.otr_session.state, OTRState.Plaintext, "Remote session state is not Plaintext")

    def test_otr_shutdown_two_way(self):
        self.local_endpoint.start_otr()
        self.remote_endpoint.start_otr()
        self.local_endpoint.ake_done.wait(1)
        self.remote_endpoint.ake_done.wait(1)
        self.local_endpoint.stop_otr()
        self.remote_endpoint.stop_otr()
        self.local_endpoint.otr_done.wait(1)
        self.remote_endpoint.otr_done.wait(1)
        self.assertIs(self.local_endpoint.otr_session.state, OTRState.Plaintext, "Local session state is not Plaintext")
        self.assertIs(self.remote_endpoint.otr_session.state, OTRState.Plaintext, "Remote session state is not Plaintext")


if __name__ == '__main__':
    log.level.current = log.level.INFO
    unittest.main(verbosity=2)
