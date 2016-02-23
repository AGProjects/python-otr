
from abc import ABCMeta, abstractmethod
from application.notification import NotificationCenter, NotificationData, IObserver
from application.python import Null
from zope.interface import implements

from otr.cryptography import PrivateKey
from otr.exceptions import IgnoreMessage, UnencryptedMessage, OTRError
from otr.protocol import OTRProtocol, OTRState, SMPStatus, QueryMessage, TaggedPlaintextMessage, ErrorMessage, MessageFragmentHandler
from otr.__info__ import __project__, __summary__, __webpage__, __version__, __author__, __email__, __license__, __copyright__


__all__ = ('OTRSession', 'OTRTransport', 'GenericOTRTransport', 'OTRState', 'SMPStatus')


class OTRTransport(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def inject_otr_message(self, message):
        raise NotImplementedError


class GenericOTRTransport(OTRTransport):
    def __init__(self, send_message_function):
        self._send_message = send_message_function

    def inject_otr_message(self, message):
        return self._send_message(message)


class OTRSession(object):
    implements(IObserver)

    def __init__(self, private_key, transport, supported_versions=OTRProtocol.supported_versions):
        if not isinstance(private_key, PrivateKey):
            raise TypeError("private_key must be a PrivateKey instance")
        if not isinstance(transport, OTRTransport):
            raise TypeError("transport must be an OTRTransport instance")
        if not OTRProtocol.supported_versions.issuperset(supported_versions):
            raise ValueError("unsupported protocol version: {!r}".format(set(supported_versions).difference(OTRProtocol.supported_versions).pop()))
        self.local_private_key = private_key
        self.transport = transport
        self.supported_versions = set(supported_versions)
        self.fragment_handler = MessageFragmentHandler()
        self.protocol = None
        self.sent_query = False

    @property
    def protocol(self):
        return self.__dict__['protocol']

    @protocol.setter
    def protocol(self, value):
        old_protocol = self.__dict__.get('protocol', None)
        new_protocol = self.__dict__['protocol'] = value
        if new_protocol is old_protocol:
            return
        notification_center = NotificationCenter()
        if old_protocol is not None:
            notification_center.remove_observer(self, sender=old_protocol)
        if new_protocol is not None:
            notification_center.add_observer(self, sender=new_protocol)

    @property
    def id(self):
        try:
            return self.protocol.session_id
        except AttributeError:
            return None

    @property
    def state(self):
        try:
            return self.protocol.state
        except AttributeError:
            return OTRState.Plaintext

    @property
    def remote_public_key(self):
        try:
            return self.protocol.remote_public_key
        except AttributeError:
            return None

    @property
    def encrypted(self):
        return self.state is OTRState.Encrypted

    def start(self):
        if self.protocol is None:
            query = QueryMessage(versions=self.supported_versions)
            self.send_message(query.encode())
            self.sent_query = True
        else:
            pass  # never restart the AKE as it creates a security risk which allows man-in-the-middle attacks even after the session was encrypted and verified using SMP

    def stop(self):
        if self.protocol is not None:
            self.protocol.stop()
            self.protocol = None
        self.sent_query = False

    def smp_verify(self, secret, question=None):
        if self.encrypted:
            self.protocol.smp_verify(secret, question)
        else:
            notification_center = NotificationCenter()
            notification_center.post_notification('OTRSessionSMPVerificationDidNotStart', sender=self, data=NotificationData(reason='not encrypted'))

    def smp_answer(self, secret):
        if self.encrypted:
            self.protocol.smp_answer(secret)

    def smp_abort(self):
        if self.encrypted:
            self.protocol.smp_abort()

    def handle_input(self, content, content_type):
        # handle fragments
        if content.startswith(('?OTR|', '?OTR,')):
            content = self.fragment_handler.process(content, protocol=self.protocol)
        else:
            self.fragment_handler.reset()

        # handle OTR messages
        if content.startswith('?OTR:'):
            if self.protocol is None and self.sent_query and content[OTRProtocol.marker_slice] in OTRProtocol.commit_markers:
                protocol_class = OTRProtocol.with_marker(content[OTRProtocol.marker_slice])
                if protocol_class.__version__ in self.supported_versions:
                    self.protocol = protocol_class(self)
            if self.protocol is not None:
                return self.protocol.handle_input(content, content_type)
        elif content.startswith('?OTR'):
            try:
                query = QueryMessage.decode(content)
            except ValueError:
                pass
            else:
                if self.protocol is None:
                    common_versions = self.supported_versions.intersection(query.versions)
                    if common_versions:
                        self.protocol = OTRProtocol.with_version(max(common_versions))(self)
                        self.protocol.start()
                else:
                    pass  # never restart the AKE as it creates a security risk which allows man-in-the-middle attacks even after the session was encrypted and verified using SMP
                raise IgnoreMessage
            try:
                error = ErrorMessage.decode(content)
            except ValueError:
                pass
            else:
                if self.protocol is not None:
                    raise OTRError(error.error)

        # handle non-OTR messages
        if self.encrypted:
            raise UnencryptedMessage
        else:
            if self.protocol is None and content_type.startswith('text/') and TaggedPlaintextMessage.__tag__.prefix in content:
                query = TaggedPlaintextMessage.decode(content)
                common_versions = self.supported_versions.intersection(query.versions)
                if common_versions:
                    self.protocol = OTRProtocol.with_version(max(common_versions))(self)
                    self.protocol.start()
                return query.message
            return content

    def handle_output(self, content, content_type):
        if self.state in (OTRState.Encrypted, OTRState.Finished):
            return self.protocol.handle_output(content, content_type)
        else:
            return content

    def send_message(self, message):
        return self.transport.inject_otr_message(message)

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_{0.name}'.format(notification), Null)
        handler(notification)

    def _NH_OTRProtocolStateChanged(self, notification):
        notification.center.post_notification('OTRSessionStateChanged', sender=self, data=notification.data)

    def _NH_OTRProtocolSMPVerificationDidStart(self, notification):
        notification.center.post_notification('OTRSessionSMPVerificationDidStart', sender=self, data=notification.data)

    def _NH_OTRProtocolSMPVerificationDidNotStart(self, notification):
        notification.center.post_notification('OTRSessionSMPVerificationDidNotStart', sender=self, data=notification.data)

    def _NH_OTRProtocolSMPVerificationDidEnd(self, notification):
        notification.center.post_notification('OTRSessionSMPVerificationDidEnd', sender=self, data=notification.data)

