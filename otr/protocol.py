
import re

from abc import ABCMeta, abstractmethod, abstractproperty
from application.notification import NotificationCenter, NotificationData
from application.python import Null
from application.python.decorator import decorator, preserve_signature
from application.python.descriptor import classproperty
from application.python.weakref import defaultweakobjectmap
from binascii import a2b_base64 as base64_decode, b2a_base64 as base64_encode
from collections import deque
from enum import Enum
from gmpy2 import powmod
from hashlib import sha1, sha256
from hmac import HMAC
from itertools import count
from random import getrandbits
from struct import Struct, pack

from otr.cryptography import DHGroup, DHGroupNumberContext, DHKeyPair, DHPrivateKey, DHPublicKey, SMPPrivateKey, SMPPublicKey, SMPExponent, SMPHash
from otr.cryptography import AESCounterCipher, DSASignatureHashContext, PublicKey
from otr.exceptions import IgnoreMessage, UnencryptedMessage, OTRFinishedError, EncryptedMessageError
from otr.util import Data, MPI, bytes_to_long, long_to_bytes, pack_data, pack_mpi, read_content, read_format


__all__ = ('QueryMessage', 'TaggedPlaintextMessage', 'ErrorMessage', 'MessageFragmentHandler', 'OTRProtocol', 'OTRState', 'SMPStatus')


#
# OTR messages
#

class GlobalMessage(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def encode(self):
        raise NotImplementedError

    @abstractmethod
    def decode(cls, message):
        raise NotImplementedError


class QueryMessage(GlobalMessage):
    def __init__(self, versions=None):
        self.versions = set(versions or OTRProtocol.supported_versions)

    def __repr__(self):
        return '{0.__class__.__name__}(versions={0.versions!r})'.format(self)

    def encode(self):
        message = u'I would like to start an Off-the-Record private conversation, but you do not seem to support that.'
        if self.versions == {1}:
            return '?OTR?  {message}'.format(message=message.encode('utf-8'))
        elif 1 in self.versions:
            return '?OTR?v{versions}?  {message}'.format(versions=''.join(str(x) for x in self.versions if x != 1), message=message.encode('utf-8'))
        else:
            return '?OTRv{versions}?  {message}'.format(versions=''.join(str(x) for x in self.versions), message=message.encode('utf-8'))

    @classmethod
    def decode(cls, message):
        if not message.startswith('?OTR'):
            raise ValueError("Not an OTR query message")

        versions = set()

        if message.startswith('?OTR?v'):
            versions_string, sep, _ = message[6:].partition('?')
            if sep != '?':
                raise ValueError("Invalid OTR query message")
            versions.add(1)
            versions.update(int(x) if x.isdigit() else x for x in versions_string)
        elif message.startswith('?OTRv'):
            versions_string, sep, _ = message[5:].partition('?')
            if sep != '?':
                raise ValueError("Invalid OTR query message")
            versions.update(int(x) if x.isdigit() else x for x in versions_string)
        elif message.startswith('?OTR?'):
            versions.add(1)
        else:
            raise ValueError("Invalid OTR query message")

        return cls(versions)


class TaggedPlaintextMessage(GlobalMessage):
    class __tag__:
        prefix = '\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20'
        versions = {1: '\x20\x09\x20\x09\x20\x20\x09\x20', 2: '\x20\x20\x09\x09\x20\x20\x09\x20', 3: '\x20\x20\x09\x09\x20\x20\x09\x09'}

    def __init__(self, message, versions=None):
        self.message = message
        self.versions = set(versions or OTRProtocol.supported_versions)

    def __repr__(self):
        return '{0.__class__.__name__}(message={0.message!r}, versions={0.versions!r})'.format(self)

    def encode(self):
        message = self.message + self.__tag__.prefix
        for version in self.versions:
            message += self.__tag__.versions[version]
        return message

    @classmethod
    def decode(cls, message):
        try:
            tag_start = message.index(cls.__tag__.prefix)
        except ValueError:
            raise ValueError("Not an OTR tagged plaintext message")

        version_tags = []
        for position in range(tag_start + 16, len(message), 8):
            token = message[position:position+8]
            if len(token) != 8 or set(token) != {'\x20', '\x09'}:
                break
            version_tags.append(token)
        versions = {version for version, tag in cls.__tag__.versions.items() if tag in version_tags}
        tag_end = tag_start + 16 + 8*len(version_tags)

        original_message = message[:tag_start] + message[tag_end:]

        return cls(original_message, versions)


class ErrorMessage(GlobalMessage):
    def __init__(self, error):
        self.error = error

    def __repr__(self):
        return '{0.__class__.__name__}(error={0.error!r})'.format(self)

    def encode(self):
        return '?OTR Error:{0.error}'.format(self)

    @classmethod
    def decode(cls, message):
        if not message.startswith('?OTR Error:'):
            raise ValueError("Not an OTR error message")
        return cls(message[11:])


class CalculateMAC(object):
    def __init__(self, key):
        self.key = key

    def __repr__(self):
        return "{0.__class__.__name__}(key={0.key!r})".format(self)


class EncodedMessageType(ABCMeta):
    __classes__ = {}
    __type__ = None

    def __init__(cls, name, bases, dictionary):
        super(EncodedMessageType, cls).__init__(name, bases, dictionary)
        if cls.__type__ is not None:
            cls.__classes__[cls.__type__] = cls

    @classproperty
    def types(mcls):
        return frozenset(mcls.__classes__)

    @classmethod
    def get(mcls, type):
        return mcls.__classes__[type]


class EncodedMessage(object):
    __metaclass__ = EncodedMessageType

    __type__ = None
    __header__ = None

    def encode(self):
        return '?OTR:' + base64_encode(self.__header__ + self.pack_data())[:-1] + '.'

    @classmethod
    def decode(cls, message, protocol):
        if not message.startswith('?OTR:') or not message.endswith('.'):
            raise ValueError("Not an OTR message")
        try:
            message = base64_decode(message[5:-1])
        except Exception:
            raise ValueError("Not an OTR message")
        message_class, message_buffer = protocol.decode_header(message)
        assert cls.__type__ is None or message_class is cls, "Expected a {.__name__} message, but got a {.__name__} message instead".format(cls, message_class)
        return message_class(*message_class.unpack_data(message_buffer), header=message[:protocol.__header__.size])

    @abstractmethod
    def pack_data(self):
        raise NotImplementedError

    @abstractmethod
    def unpack_data(message):
        raise NotImplementedError

    @abstractmethod
    def new(cls, protocol):
        raise NotImplementedError


class DHCommitMessage(EncodedMessage):
    __type__ = 0x02

    def __init__(self, encrypted_gx, hashed_gx, header):
        self.__header__ = header
        self.encrypted_gx = encrypted_gx
        self.hashed_gx = hashed_gx

    def __repr__(self):
        return '{0.__class__.__name__}(encrypted_gx={0.encrypted_gx!r}, hashed_gx={0.hashed_gx!r}, header={0.__header__!r})'.format(self)

    def pack_data(self):
        return pack_data(self.encrypted_gx) + pack_data(self.hashed_gx)

    @staticmethod
    def unpack_data(message):
        return read_content(message, Data, Data)

    @classmethod
    def new(cls, protocol):
        return cls(protocol.ake.encrypted_gx, protocol.ake.hashed_gx, protocol.encode_header(cls))


class DHKeyMessage(EncodedMessage):
    __type__ = 0x0a

    def __init__(self, gx, header):
        self.__header__ = header
        self.gx = gx

    def __repr__(self):
        return '{0.__class__.__name__}(gy={0.gx!r}, header={0.__header__!r})'.format(self)

    def pack_data(self):
        return pack_mpi(self.gx)

    @staticmethod
    def unpack_data(message):
        return read_content(message, MPI),

    @classmethod
    def new(cls, protocol):
        return cls(protocol.ake.gx, protocol.encode_header(cls))


class RevealSignatureMessage(EncodedMessage):
    __type__ = 0x11

    def __init__(self, revealed_key, encrypted_signature, signature_mac, header):
        self.__header__ = header
        self.revealed_key = revealed_key
        self.encrypted_signature = encrypted_signature
        self.signature_mac = self.calculate_mac(signature_mac.key) if isinstance(signature_mac, CalculateMAC) else signature_mac

    def __repr__(self):
        return '{0.__class__.__name__}(revealed_key={0.revealed_key!r}, encrypted_signature={0.encrypted_signature!r}, signature_mac={0.signature_mac!r}, header={0.__header__!r})'.format(self)

    def pack_data(self):
        return pack_data(self.revealed_key) + pack_data(self.encrypted_signature) + self.signature_mac

    @staticmethod
    def unpack_data(message):
        return read_content(message, Data, Data, '20s')

    @classmethod
    def new(cls, protocol):
        return cls(protocol.ake.r, protocol.calculate_encrypted_signature(protocol.ake.aes_c, protocol.ake.mac_m1), CalculateMAC(key=protocol.ake.mac_m2), protocol.encode_header(cls))

    def calculate_mac(self, key):
        return HMAC(key, pack_data(self.encrypted_signature), sha256).digest()[:20]

    def validate_mac(self, key):
        if self.signature_mac != self.calculate_mac(key):
            raise ValueError("The signature's MAC doesn't match")


class SignatureMessage(EncodedMessage):
    __type__ = 0x12

    def __init__(self, encrypted_signature, signature_mac, header):
        self.__header__ = header
        self.encrypted_signature = encrypted_signature
        self.signature_mac = self.calculate_mac(signature_mac.key) if isinstance(signature_mac, CalculateMAC) else signature_mac

    def __repr__(self):
        return '{0.__class__.__name__}(encrypted_signature={0.encrypted_signature!r}, signature_mac={0.signature_mac!r}, header={0.__header__!r})'.format(self)

    def pack_data(self):
        return pack_data(self.encrypted_signature) + self.signature_mac

    @staticmethod
    def unpack_data(message):
        return read_content(message, Data, '20s')

    @classmethod
    def new(cls, protocol):
        return cls(protocol.calculate_encrypted_signature(protocol.ake.aes_cp, protocol.ake.mac_m1p), CalculateMAC(key=protocol.ake.mac_m2p), protocol.encode_header(cls))

    def calculate_mac(self, key):
        return HMAC(key, pack_data(self.encrypted_signature), sha256).digest()[:20]

    def validate_mac(self, key):
        if self.signature_mac != self.calculate_mac(key):
            raise ValueError("The signature's MAC doesn't match")


class DataMessage(EncodedMessage):
    __type__ = 0x03

    def __init__(self, flags, sender_keyid, recipient_keyid, next_public_key, counter, encrypted_message, mac, old_macs, header):
        self.__header__ = header
        self.__signed_content = pack('!BII', flags, sender_keyid, recipient_keyid) + pack_mpi(next_public_key) + pack('!Q', counter) + pack_data(encrypted_message)
        self.flags = flags
        self.sender_keyid = sender_keyid
        self.recipient_keyid = recipient_keyid
        self.next_public_key = next_public_key
        self.counter = counter
        self.encrypted_message = encrypted_message
        self.mac = self.calculate_mac(mac.key) if isinstance(mac, CalculateMAC) else mac
        self.old_macs = old_macs

    def __repr__(self):
        return '{0.__class__.__name__}(flags={0.flags!r}, sender_keyid={0.sender_keyid!r}, recipient_keyid={0.recipient_keyid!r}, next_public_key={0.next_public_key!r}, counter={0.counter!r}, encrypted_message={0.encrypted_message!r}, mac={0.mac!r}, old_macs={0.old_macs!r}, header={0.__header__!r})'.format(self)

    def pack_data(self):
        return self.__signed_content + self.mac + pack_data(self.old_macs)

    @staticmethod
    def unpack_data(message):
        return read_content(message, '!BII', MPI, '!Q', Data, '20s', Data)

    @classmethod
    def new(cls, protocol, content='', tlv_records=()):
        if tlv_records:
            if '\0' in content:
                raise ValueError("cannot attach TLVs to a message that has Null bytes in it")
            content += '\0' + TLVRecords.encode(tlv_records)
        current_dh_key, next_dh_key = protocol.dh_local_private_keys
        sender_keyid, recipient_keyid = DHKeyPair(current_dh_key, protocol.dh_remote_public_keys.latest).id
        session_key = protocol.session_keys[sender_keyid, recipient_keyid]
        session_key.outgoing_counter += 1
        header = protocol.encode_header(cls)
        encrypted_message = AESCounterCipher(session_key.outgoing_key, session_key.outgoing_counter).encrypt(content)
        old_macs = ''.join(protocol.session_keys.old_macs)
        protocol.session_keys.old_macs = []
        return cls(0, sender_keyid, recipient_keyid, next_dh_key.public_key, session_key.outgoing_counter, encrypted_message, CalculateMAC(key=session_key.outgoing_mac), old_macs, header)

    def calculate_mac(self, key):
        assert self.__header__ is not None, "Cannot calculate the message MAC without a header"
        return HMAC(key, self.__header__ + self.__signed_content, sha1).digest()

    def validate(self, previous_counter, mac_key):
        if self.counter <= previous_counter:
            raise ValueError("The message counter should be monotonically increasing")
        if self.mac != self.calculate_mac(mac_key):
            raise ValueError("The message MAC doesn't match")
        if not DHPublicKey.is_valid(self.next_public_key):
            raise ValueError("The next DH public key is invalid")


class MessageFragmentHandler(object):
    fragment_re = re.compile(r'^\?OTR(?:\|(?P<sender_tag>[0-9a-fA-F]{1,8})\|(?P<recipient_tag>[0-9a-fA-F]{1,8}))?,(?P<k>\d{1,5}),(?P<n>\d{1,5}),(?P<message>.*),$')  # faster without re.I

    def __init__(self):
        self.message = ''
        self.k = 0
        self.n = 0

    def process(self, data, protocol=None):
        try:
            sender_tag, recipient_tag, k, n, message = self.fragment_re.match(data).groups()
            if sender_tag is not None:
                sender_tag = int(sender_tag, 16)
            if recipient_tag is not None:
                recipient_tag = int(recipient_tag, 16)
            k = int(k)
            n = int(n)
        except (AttributeError, ValueError):
            self.reset()
            return data  # not a fragment
        if hasattr(protocol, 'local_tag'):
            if recipient_tag is None:
                self.reset()
                return data  # fragment doesn't match protocol (expected to have instance tags)
            elif recipient_tag != 0 and recipient_tag != protocol.local_tag:
                raise IgnoreMessage
        if k == 0 or n == 0 or k > n:
            raise IgnoreMessage  # invalid fragment (return the data here?)
        if k == 1:
            self.message = message
            self.k = k
            self.n = n
        elif k == self.k+1 and n == self.n:
            self.message += message
            self.k = k
        else:
            self.reset()  # out of order fragment (return the data here?)
        if self.k == self.n > 0:
            return self.message
        else:
            raise IgnoreMessage

    def reset(self):
        self.message = ''
        self.k = 0
        self.n = 0


#
# TLV records
#

class TLVRecordType(ABCMeta):
    __classes__ = {}
    __type__ = None

    def __init__(cls, name, bases, dictionary):
        super(TLVRecordType, cls).__init__(name, bases, dictionary)
        if cls.__type__ is not None:
            cls.__classes__[cls.__type__] = cls

    @classmethod
    def get(mcls, type):
        return mcls.__classes__[type]


class TLVRecord(object):
    __metaclass__ = TLVRecordType

    __type__ = None

    __header__ = Struct('!HH')

    def encode(self):
        data = self.pack_data()
        return self.__header__.pack(self.__type__, len(data)) + data

    @classmethod
    def decode(cls, record):
        type, length, data = read_format(cls.__header__.format, record)
        if len(data) < length:
            raise ValueError("Not enough data bytes in message")
        record_class = cls.get(type)
        assert cls.__type__ is None or record_class is cls, "Expected a {.__name__} record, but got a {.__name__} record instead".format(cls, record_class)
        return record_class(*record_class.unpack_data(data[:length]))

    @abstractmethod
    def pack_data(self):
        raise NotImplementedError

    @abstractmethod
    def unpack_data(cls, buffer):
        raise NotImplementedError


class SMPMessageTLV(TLVRecord):
    __type__ = None
    __size__ = None

    @abstractproperty
    def mpi_list(self):
        raise NotImplementedError

    def pack_data(self):
        return pack('!I', self.__size__) + ''.join(pack_mpi(mpi) for mpi in self.mpi_list)

    @classmethod
    def unpack_data(cls, data):
        size, mpi_data = read_format('!I', data)
        if size != cls.__size__:
            raise ValueError("Expected {} MPIs, got {}".format(cls.__size__, size))
        return read_content(mpi_data, *(size*[MPI]))

    @abstractmethod
    def new(cls, protocol):
        raise NotImplementedError


class PaddingTLV(TLVRecord):
    __type__ = 0

    def __init__(self, padding):
        self.padding = padding

    def pack_data(self):
        return self.padding

    @classmethod
    def unpack_data(cls, data):
        return data,


class DisconnectTLV(TLVRecord):
    __type__ = 1

    def pack_data(self):
        return ''

    @classmethod
    def unpack_data(cls, data):
        if data:
            raise ValueError('{0.__name__} must not contain any data (got {1!r})'.format(cls, data))
        return ()


class SMPMessage1(SMPMessageTLV):
    __type__ = 2
    __size__ = 6

    def __init__(self, g2a, c2, d2, g3a, c3, d3):
        self.g2a = SMPPublicKey(g2a)
        self.c2 = SMPHash(c2)
        self.d2 = SMPExponent(d2)
        self.g3a = SMPPublicKey(g3a)
        self.c3 = SMPHash(c3)
        self.d3 = SMPExponent(d3)

    @property
    def mpi_list(self):
        return self.g2a, self.c2, self.d2, self.g3a, self.c3, self.d3

    @classmethod
    def new(cls, protocol):
        c2, d2 = protocol.smp.create_proof_known_logarithm(protocol.smp.a2, 1)
        c3, d3 = protocol.smp.create_proof_known_logarithm(protocol.smp.a3, 2)
        return cls(protocol.smp.a2.public_key, c2, d2, protocol.smp.a3.public_key, c3, d3)

    def validate(self, protocol):
        protocol.smp.verify_proof_known_logarithm(self.g2a, self.c2, self.d2, 1)
        protocol.smp.verify_proof_known_logarithm(self.g3a, self.c3, self.d3, 2)


class SMPMessage1Q(SMPMessage1):
    __type__ = 7
    __size__ = 6

    def __init__(self, g2a, c2, d2, g3a, c3, d3, question=''):
        super(SMPMessage1Q, self).__init__(g2a, c2, d2, g3a, c3, d3)
        self.question = question

    def pack_data(self):
        return self.question + '\x00' + super(SMPMessage1Q, self).pack_data()

    @classmethod
    def unpack_data(cls, data):
        question, separator, data = data.partition('\x00')
        return super(SMPMessage1Q, cls).unpack_data(data) + (question,)

    @classmethod
    def new(cls, protocol, question=''):
        instance = super(SMPMessage1Q, cls).new(protocol)
        instance.question = question
        return instance


class SMPMessage2(SMPMessageTLV):
    __type__ = 3
    __size__ = 11

    def __init__(self, g2a, c2, d2, g3a, c3, d3, pa, qa, cp, d5, d6):
        self.g2a = SMPPublicKey(g2a)
        self.c2 = SMPHash(c2)
        self.d2 = SMPExponent(d2)
        self.g3a = SMPPublicKey(g3a)
        self.c3 = SMPHash(c3)
        self.d3 = SMPExponent(d3)
        self.pa = SMPPublicKey(pa)
        self.qa = SMPPublicKey(qa)
        self.cp = SMPHash(cp)
        self.d5 = SMPExponent(d5)
        self.d6 = SMPExponent(d6)

    @property
    def mpi_list(self):
        return self.g2a, self.c2, self.d2, self.g3a, self.c3, self.d3, self.pa, self.qa, self.cp, self.d5, self.d6

    @classmethod
    def new(cls, protocol):
        c2, d2 = protocol.smp.create_proof_known_logarithm(protocol.smp.a2, 3)
        c3, d3 = protocol.smp.create_proof_known_logarithm(protocol.smp.a3, 4)
        cp, d5, d6 = protocol.smp.create_proof_known_coordinates(5)
        return cls(protocol.smp.a2.public_key, c2, d2, protocol.smp.a3.public_key, c3, d3, protocol.smp.pa, protocol.smp.qa, cp, d5, d6)

    def validate(self, protocol):
        protocol.smp.verify_proof_known_logarithm(self.g2a, self.c2, self.d2, 3)
        protocol.smp.verify_proof_known_logarithm(self.g3a, self.c3, self.d3, 4)
        protocol.smp.verify_proof_known_coordinates(self.pa, self.qa, self.cp, self.d5, self.d6, 5)


class SMPMessage3(SMPMessageTLV):
    __type__ = 4
    __size__ = 8

    def __init__(self, pa, qa, cp, d5, d6, ra, cr, d7):
        self.pa = SMPPublicKey(pa)
        self.qa = SMPPublicKey(qa)
        self.cp = SMPHash(cp)
        self.d5 = SMPExponent(d5)
        self.d6 = SMPExponent(d6)
        self.ra = SMPPublicKey(ra)
        self.cr = SMPHash(cr)
        self.d7 = SMPExponent(d7)

    @property
    def mpi_list(self):
        return self.pa, self.qa, self.cp, self.d5, self.d6, self.ra, self.cr, self.d7

    @classmethod
    def new(cls, protocol):
        cp, d5, d6 = protocol.smp.create_proof_known_coordinates(6)
        cr, d7 = protocol.smp.create_proof_equal_logarithms(7)
        return cls(protocol.smp.pa, protocol.smp.qa, cp, d5, d6, protocol.smp.ra, cr, d7)

    def validate(self, protocol):
        protocol.smp.verify_proof_known_coordinates(self.pa, self.qa, self.cp, self.d5, self.d6, 6)
        protocol.smp.verify_proof_equal_logarithms(self.ra, self.cr, self.d7, 7)


class SMPMessage4(SMPMessageTLV):
    __type__ = 5
    __size__ = 3

    def __init__(self, ra, cr, d7):
        self.ra = SMPPublicKey(ra)
        self.cr = SMPHash(cr)
        self.d7 = SMPExponent(d7)

    @property
    def mpi_list(self):
        return self.ra, self.cr, self.d7

    @classmethod
    def new(cls, protocol):
        cr, d7 = protocol.smp.create_proof_equal_logarithms(8)
        return cls(protocol.smp.ra, cr, d7)

    def validate(self, protocol):
        protocol.smp.verify_proof_equal_logarithms(self.ra, self.cr, self.d7, 8)


class SMPAbortMessage(TLVRecord):
    __type__ = 6

    def pack_data(self):
        return ''

    @classmethod
    def unpack_data(cls, data):
        if data:
            raise ValueError('{0.__name__} must not contain any data (got {1!r})'.format(cls, data))
        return ()


class ExtraKeyTLV(TLVRecord):
    __type__ = 8

    def __init__(self, scope, data=None):
        if not isinstance(scope, basestring) or not isinstance(data, (basestring, type(None))):
            raise TypeError("scope must be a string and data must be a string or None")
        if len(scope) != 4:
            raise ValueError("scope must be a 4 character string")
        self.scope = scope
        self.data = data

    def pack_data(self):
        return self.scope + self.data if self.data else self.scope

    @classmethod
    def unpack_data(cls, data):
        scope, data = read_format('4s', data)
        return scope, data or None


class TLVRecords(object):
    @staticmethod
    def encode(tlv_list):
        return ''.join(tlv.encode() for tlv in tlv_list)

    @staticmethod
    def decode(buffer):
        records = []
        while buffer:
            type, length, data = read_format(TLVRecord.__header__.format, buffer)
            if len(data) < length:
                raise ValueError("Not enough data bytes in message")
            data, buffer = data[:length], data[length:]
            record_class = TLVRecord.get(type)
            records.append(record_class(*record_class.unpack_data(data)))
        return records


#
# Protocol handlers
#

class DHKeyQueue(object):
    def __init__(self):
        self.__items__ = deque(maxlen=2)
        self.__keyid__ = count(1)
        self.__dirty__ = False

    def __getitem__(self, key_id):
        return next((item for item in self.__items__ if item.__id__ == key_id), None)

    def __contains__(self, key_id):
        return key_id in (item.__id__ for item in self.__items__)

    def __iter__(self):
        return iter(self.__items__)

    def __reversed__(self):
        return reversed(self.__items__)

    def __len__(self):
        return len(self.__items__)

    @property
    def latest(self):
        return next(reversed(self.__items__), None)

    def add(self, item):
        if item.__id__ is None:
            item.__id__ = next(self.__keyid__)
        else:
            self.__keyid__ = count(int(item.__id__) + 1)
        self.__items__.append(item)
        self.__dirty__ = True

    def clear(self):
        self.__items__.clear()
        self.__keyid__ = count(1)
        self.__dirty__ = True


class SessionKeyMAC(str):
    def __new__(cls, key):
        instance = super(SessionKeyMAC, cls).__new__(cls, sha1(key).digest())
        instance.used = False
        return instance


class SessionKey(object):
    def __init__(self, outgoing_key, incoming_key):
        self.outgoing_key = outgoing_key
        self.incoming_key = incoming_key
        self.outgoing_mac = SessionKeyMAC(outgoing_key)
        self.incoming_mac = SessionKeyMAC(incoming_key)
        self.outgoing_counter = 0
        self.incoming_counter = 0

    @classmethod
    def new(cls, private_key, public_key):
        secret = powmod(public_key, private_key, private_key.prime)
        secret_string = pack_mpi(secret)
        key1 = sha1('\x01' + secret_string).digest()[:16]
        key2 = sha1('\x02' + secret_string).digest()[:16]
        if private_key.public_key > public_key:
            outgoing_key, incoming_key = key1, key2
        else:
            outgoing_key, incoming_key = key2, key1
        return cls(outgoing_key, incoming_key)


class SessionKeysMapping(dict):
    def __init__(self, *args, **kw):
        super(SessionKeysMapping, self).__init__(*args, **kw)
        self.old_macs = []


class SessionKeysDescriptor(object):
    def __init__(self):
        self.values = defaultweakobjectmap(SessionKeysMapping)

    def __get__(self, instance, owner):
        if instance is None:
            return self
        session_keys = self.values[instance]
        if instance.dh_local_private_keys.__dirty__ or instance.dh_remote_public_keys.__dirty__:
            key_pairs = [DHKeyPair(private_key, public_key) for private_key in instance.dh_local_private_keys for public_key in instance.dh_remote_public_keys]
            for key_id in set(session_keys).difference(key_pair.id for key_pair in key_pairs):
                key = session_keys.pop(key_id)
                if key.outgoing_mac.used:
                    session_keys.old_macs.append(key.outgoing_mac)
                if key.incoming_mac.used:
                    session_keys.old_macs.append(key.incoming_mac)
            for key_pair in (key_pair for key_pair in key_pairs if key_pair.id not in session_keys):
                session_keys[key_pair.id] = SessionKey.new(key_pair.private_key, key_pair.public_key)
            instance.dh_local_private_keys.__dirty__ = instance.dh_remote_public_keys.__dirty__ = False
        return session_keys

    def __set__(self, instance, value):
        raise AttributeError("Attribute cannot be set")

    def __delete__(self, instance):
        raise AttributeError("Attribute cannot be deleted")


class OTRState(Enum):
    Plaintext = 'Plaintext'
    Encrypted = 'Encrypted'
    Finished = 'Finished'


class AKEState(Enum):
    AwaitingDHKey = 'AwaitingDHKey'
    AwaitingRevealSignature = 'AwaitingRevealSignature'
    AwaitingSignature = 'AwaitingSignature'


class SMPState(Enum):
    ExpectMessage1 = 'ExpectMessage1'
    ExpectMessage2 = 'ExpectMessage2'
    ExpectMessage3 = 'ExpectMessage3'
    ExpectMessage4 = 'ExpectMessage4'
    AwaitingUserSecret = 'AwaitingUserSecret'


class SMPStatus(Enum):
    Success = 'Success'
    Interrupted = 'Interrupted'
    ProtocolError = 'ProtocolError'


class AuthenticatedKeyExchange(object):
    def __init__(self, dh_key):
        self.dh_key = dh_key

        self.r = long_to_bytes(getrandbits(128), 16)

        self.gx = dh_key.public_key
        self.encrypted_gx = AESCounterCipher(self.r).encrypt(pack_mpi(self.gx))
        self.hashed_gx = sha256(pack_mpi(self.gx)).digest()

        self.gy = None
        self.encrypted_gy = None
        self.hashed_gy = None

        self.state = None

    @property
    def secret(self):
        return self.__dict__['secret']

    @property
    def session_id(self):
        return sha256('\x00' + pack_mpi(self.secret)).digest()[:8] if self.secret is not None else None

    @property
    def aes_c(self):
        return sha256('\x01' + pack_mpi(self.secret)).digest()[:16] if self.secret is not None else None

    @property
    def aes_cp(self):
        return sha256('\x01' + pack_mpi(self.secret)).digest()[16:] if self.secret is not None else None

    @property
    def mac_m1(self):
        return sha256('\x02' + pack_mpi(self.secret)).digest() if self.secret is not None else None

    @property
    def mac_m2(self):
        return sha256('\x03' + pack_mpi(self.secret)).digest() if self.secret is not None else None

    @property
    def mac_m1p(self):
        return sha256('\x04' + pack_mpi(self.secret)).digest() if self.secret is not None else None

    @property
    def mac_m2p(self):
        return sha256('\x05' + pack_mpi(self.secret)).digest() if self.secret is not None else None

    @property
    def extra_key(self):
        return sha256('\xff' + pack_mpi(self.secret)).digest() if self.secret is not None else None

    @property
    def gy(self):
        return self.__dict__['gy']

    @gy.setter
    def gy(self, value):
        self.__dict__['gy'] = value
        self.__dict__['secret'] = long(powmod(value, self.dh_key, self.dh_key.prime)) if value is not None else None


class SocialistMillionairesProtocol(object):
    ignore_next_abort = False  # use a class level attribute to avoid it being cleared during reset()

    def __init__(self):
        self.g1 = DHGroup.generator
        self.g2 = None
        self.g3 = None

        self.a2 = SMPPrivateKey()
        self.a3 = SMPPrivateKey()

        self.g2a = self.a2.public_key
        self.g3a = self.a3.public_key
        self.g2b = None
        self.g3b = None

        self.r = SMPPrivateKey()  # this random key will be used to compute pa and qa later, as well as the proof of knowledge of discrete coordinates
        self.pa = None
        self.qa = None
        self.pb = None
        self.qb = None
        self.pab = None  # this is always P_originator/P_respondent, that is Pa/Pb if we originated SMP else Pb/Pa
        self.qab = None  # this is always Q_originator/Q_respondent, that is Qa/Qb if we originated SMP else Qb/Qa

        self.ra = None
        self.rb = None
        self.rab = None

        self.question = None
        self.secret = None

        self.state = SMPState.ExpectMessage1

    @property
    def in_progress(self):
        return self.state is not SMPState.ExpectMessage1

    def reset(self):  # expensive: 14.6ms
        self.__init__()

    @staticmethod
    def hash(version, mpi1, mpi2=None):
        if mpi2 is None:
            return bytes_to_long(sha256(chr(version) + pack_mpi(mpi1)).digest())
        else:
            return bytes_to_long(sha256(chr(version) + pack_mpi(mpi1) + pack_mpi(mpi2)).digest())

    #
    # The zero-knowledge proofs are described in section 2.3 of the paper "A fair and efficient solution to the socialist millionaires' problem",
    # Discrete Applied Mathematics, 111(1-2):23-36, 2001 (http://www.sciencedirect.com/science/article/pii/S0166218X00003425)
    #

    def create_proof_known_logarithm(self, x, version):  # expensive: 4.86ms
        """Create proof of knowledge of a discrete logarithm"""
        r = SMPPrivateKey()
        c = self.hash(version, r.public_key)
        with DHGroupNumberContext(modulo=DHGroup.order):
            d = r - x * c
        return c, d

    def verify_proof_known_logarithm(self, gx, c, d, version):  # expensive: 5.66ms
        """Verify proof of knowledge of a discrete logarithm"""
        if c != self.hash(version, self.g1**d * gx**c):
            raise ValueError("failed to verify proof of knowledge of a discrete logarithm")

    def create_proof_known_coordinates(self, version):  # expensive: 14.7ms
        """Create proof of knowledge of discrete coordinates"""
        r1 = SMPPrivateKey(generator=self.g1)
        r2 = SMPPrivateKey(generator=self.g2)
        c = self.hash(version, self.g3**r1, r1.public_key * r2.public_key)  # hash(version, g3^r1, g1^r1 * g2^r2)
        with DHGroupNumberContext(modulo=DHGroup.order):
            d1 = r1 - self.r * c
            d2 = r2 - self.secret * c
        return c, d1, d2

    def verify_proof_known_coordinates(self, p, q, c, d1, d2, version):  # expensive: 16.1ms
        """Verify proof of knowledge of discrete coordinates"""
        if c != self.hash(version, self.g3**d1 * p**c, self.g1**d1 * self.g2**d2 * q**c):
            raise ValueError("failed to verify proof of knowledge of discrete coordinates")

    def create_proof_equal_logarithms(self, version):  # expensive: 14.5ms
        """Create proof of equality of two discrete logarithms"""
        r = SMPPrivateKey()
        c = self.hash(version, self.g1**r, self.qab**r)
        with DHGroupNumberContext(modulo=DHGroup.order):
            d = r - self.a3 * c
        return c, d

    def verify_proof_equal_logarithms(self, r, c, d, version):  # expensive: 11.4ms
        """Verify proof of equality of two discrete logarithms"""
        if c != self.hash(version, self.g1**d * (self.g3a if r == self.ra else self.g3b)**c, self.qab**d * r**c):
            raise ValueError("failed to verify proof of equality of two discrete logarithms")


@decorator
def smp_message_handler(expected_state):
    def smp_message_handler_wrapper(function):
        @preserve_signature(function)
        def function_wrapper(self, tlv):
            """@type self: OTRProtocol"""
            try:
                if self.smp.state is SMPState.ExpectMessage2 and expected_state is SMPState.ExpectMessage1:
                    self.smp.ignore_next_abort = True  # if a collision happens both parties will send an abort, which could cancel the next SMP exchange if it starts too soon
                    raise ValueError('startup collision')
                elif self.smp.state is not expected_state:
                    raise ValueError('received {0.__class__.__name__} out of order'.format(tlv))
                function(self, tlv)
            except ValueError, e:
                self._smp_terminate(status=SMPStatus.ProtocolError, reason=str(e), send_abort=True)
        return function_wrapper
    return smp_message_handler_wrapper


class OTRProtocolType(ABCMeta):
    __classes__ = {}
    __markers__ = {}
    __version__ = None

    def __init__(cls, name, bases, dictionary):
        super(OTRProtocolType, cls).__init__(name, bases, dictionary)
        if cls.__version__ is not None:
            commit_marker = base64_encode(pack('!HB', cls.__version__, DHCommitMessage.__type__)).rstrip()
            cls.__classes__[cls.__version__] = cls
            cls.__markers__[commit_marker] = cls

    @classproperty
    def supported_versions(cls):
        return set(cls.__classes__)

    @classproperty
    def commit_markers(cls):
        return set(cls.__markers__)

    @classproperty
    def marker_slice(cls):
        return slice(5, 9)

    @classmethod
    def with_version(mcls, version):
        return mcls.__classes__[version]

    @classmethod
    def with_marker(mcls, marker):
        return mcls.__markers__[marker]


class OTRProtocol(object):
    __metaclass__ = OTRProtocolType

    __version__ = None

    __header__ = None

    session_keys = SessionKeysDescriptor()

    def __init__(self, session):
        self.session = session
        self.local_private_key = session.local_private_key
        self.remote_public_key = None
        self.dh_local_private_keys = DHKeyQueue()
        self.dh_remote_public_keys = DHKeyQueue()
        self.session_id = None
        self.extra_key = None
        self.state = OTRState.Plaintext
        self.ake = Null
        self.smp = Null
        self._stop_requested = False

    @property
    def state(self):
        return self.__dict__['state']

    @state.setter
    def state(self, value):
        old_state = self.__dict__.get('state', OTRState.Plaintext)
        new_state = self.__dict__['state'] = value
        if new_state != old_state:
            notification_center = NotificationCenter()
            notification_center.post_notification('OTRProtocolStateChanged', sender=self, data=NotificationData(old_state=old_state, new_state=new_state))

    def start(self):
        if self.state is OTRState.Plaintext and self.ake is Null:
            self.dh_local_private_keys.clear()
            self.dh_remote_public_keys.clear()
            self.session_keys.old_macs = []
            self.dh_local_private_keys.add(DHPrivateKey())
            self.ake = AuthenticatedKeyExchange(self.dh_local_private_keys.latest)
            self.send_message(DHCommitMessage.new(self))
            self.ake.state = AKEState.AwaitingDHKey

    def stop(self):
        if self.state is OTRState.Encrypted:
            self._smp_terminate(status=SMPStatus.Interrupted, reason='encryption ended', send_abort=self.smp.in_progress)
            self.send_tlv(DisconnectTLV())
            self.remote_public_key = None
            self.session_id = None
            self.extra_key = None
            self.smp = Null
            self.state = OTRState.Plaintext
        elif self.state is OTRState.Finished:
            self.state = OTRState.Plaintext
        elif self.ake is not Null:
            self._stop_requested = True

    def smp_verify(self, secret, question=None):
        notification_center = NotificationCenter()
        if self.state is not OTRState.Encrypted:
            notification_center.post_notification('OTRProtocolSMPVerificationDidNotStart', sender=self, data=NotificationData(reason='not encrypted'))
        elif self.smp.in_progress:
            notification_center.post_notification('OTRProtocolSMPVerificationDidNotStart', sender=self, data=NotificationData(reason='in progress'))
        else:
            self.smp.question = question
            self.smp.secret = bytes_to_long(sha256('\1' + self.local_private_key.public_key.fingerprint + self.remote_public_key.fingerprint + self.session_id + secret).digest())
            self.send_tlv(SMPMessage1.new(self) if question is None else SMPMessage1Q.new(self, question))
            self.smp.state = SMPState.ExpectMessage2
            notification_center.post_notification('OTRProtocolSMPVerificationDidStart', sender=self, data=NotificationData(originator='local', question=question))

    def smp_answer(self, secret):
        if self.smp.state is SMPState.AwaitingUserSecret:
            self.smp.secret = bytes_to_long(sha256('\1' + self.remote_public_key.fingerprint + self.local_private_key.public_key.fingerprint + self.session_id + secret).digest())
            self.smp.pa = self.smp.g3 ** self.smp.r                             # pa = g3^r
            self.smp.qa = self.smp.r.public_key * self.smp.g2**self.smp.secret  # qa = g1^r * g2^secret
            self.send_tlv(SMPMessage2.new(self))
            self.smp.state = SMPState.ExpectMessage3

    def smp_abort(self):
        self._smp_terminate(status=SMPStatus.Interrupted, reason='cancelled', send_abort=self.smp.in_progress)

    def _smp_terminate(self, status, reason=None, same_secrets=None, send_abort=False):
        assert status is SMPStatus.Success or same_secrets is None
        if send_abort and self.state is OTRState.Encrypted:
            self.send_tlv(SMPAbortMessage())
        if self.smp.in_progress:
            notification_center = NotificationCenter()
            notification_center.post_notification('OTRProtocolSMPVerificationDidEnd', sender=self, data=NotificationData(status=status, reason=reason, same_secrets=same_secrets))
            self.smp.reset()

    def handle_input(self, content, content_type):
        try:
            message = EncodedMessage.decode(content, protocol=self)
        except ValueError:
            if self.state is OTRState.Encrypted:
                raise UnencryptedMessage
            else:
                return content
        if isinstance(message, DataMessage):
            message.content_type = content_type
        handler = getattr(self, '_MH_{0.__class__.__name__}'.format(message))
        try:
            result = handler(message)
        except ValueError:
            raise IgnoreMessage
        else:
            if result is None:
                raise IgnoreMessage
            return result

    def handle_output(self, content, content_type):
        if self.state is OTRState.Encrypted:
            # todo: automatically add a PaddingTLV with a random payload to the message if text/*? have a setting on the session to enable/disable it?
            return DataMessage.new(self, content).encode()
        elif self.state is OTRState.Finished:
            raise OTRFinishedError('The other party has ended the private conversation, you should do the same')
        else:
            return content

    def send_message(self, message):
        self.session.send_message(message.encode())

    def send_tlv(self, tlv):
        self.send_message(DataMessage.new(self, tlv_records=[tlv]))

    # def send_tlv_records(self, *tlv_records):
    #     self.send_message(DataMessage.new(self, tlv_records=tlv_records))

    @abstractmethod
    def encode_header(self, message_class):
        raise NotImplementedError

    @abstractmethod
    def decode_header(self, message):  # returns message_class, message_buffer
        raise NotImplementedError

    # signing is expensive (2.2ms). encrypting adds another 0.15ms (this is for 2048 bit keys. for 1024 bit keys, is less expensive: 0.5ms + 0.15ms)
    def calculate_encrypted_signature(self, aes_key, mac_key):
        encoded_public_key = self.local_private_key.public_key.encode()
        encoded_key_id = pack('!I', self.ake.dh_key.__id__)
        data = pack_mpi(self.ake.gx) + pack_mpi(self.ake.gy) + encoded_public_key + encoded_key_id
        signed_data = self.local_private_key.sign(data, DSASignatureHashContext(mac_key, self.local_private_key))
        return AESCounterCipher(aes_key).encrypt(encoded_public_key + encoded_key_id + signed_data)

    # verifying is expensive (2.6ms). decrypting adds another 0.15ms (this is for 2048 bit keys. for 1024 bit keys, is less expensive: 0.6ms + 0.15ms)
    def process_encrypted_signature(self, encrypted_signature, aes_key, mac_key):
        data = AESCounterCipher(aes_key).decrypt(encrypted_signature)
        public_key = PublicKey.decode(data)
        encoded_public_key = public_key.encode()
        key_id, signed_data = read_format('!I', data, offset=len(encoded_public_key))
        if key_id == 0:
            raise ValueError('invalid key id (must be strictly positive)')
        data = pack_mpi(self.ake.gy) + pack_mpi(self.ake.gx) + encoded_public_key + pack('!I', key_id)
        public_key.verify(signed_data, data, DSASignatureHashContext(mac_key, public_key))
        return public_key, key_id

    # Encoded message handlers

    def _MH_DHCommitMessage(self, message):
        if self.ake.state is AKEState.AwaitingDHKey and self.ake.hashed_gx > message.hashed_gx:
            # this here basically re-sends the last message
            self.send_message(DHCommitMessage.new(self))
        elif self.state is OTRState.Plaintext:
            if self.ake is Null:
                self.dh_local_private_keys.clear()
                self.dh_remote_public_keys.clear()
                self.session_keys.old_macs = []
                self.dh_local_private_keys.add(DHPrivateKey())
                self.ake = AuthenticatedKeyExchange(self.dh_local_private_keys.latest)
            self.ake.encrypted_gy = message.encrypted_gx
            self.ake.hashed_gy = message.hashed_gx
            self.send_message(DHKeyMessage.new(self))
            self.ake.state = AKEState.AwaitingRevealSignature

    def _MH_DHKeyMessage(self, message):
        if self.ake.state is AKEState.AwaitingDHKey:
            self.ake.gy = DHPublicKey(message.gx)
            self.send_message(RevealSignatureMessage.new(self))
            self.ake.state = AKEState.AwaitingSignature
        elif self.ake.state is AKEState.AwaitingSignature:
            if self.ake.gy == message.gx:
                # this here basically re-sends the last message
                self.send_message(RevealSignatureMessage.new(self))

    def _MH_RevealSignatureMessage(self, message):
        if self.ake.state is AKEState.AwaitingRevealSignature:
            self.ake.r = message.revealed_key
            gy_bytes = AESCounterCipher(self.ake.r).decrypt(self.ake.encrypted_gy)
            if sha256(gy_bytes).digest() != self.ake.hashed_gy:
                raise ValueError('gy hash mismatch')
            self.ake.gy = DHPublicKey(read_content(gy_bytes, MPI))
            message.validate_mac(key=self.ake.mac_m2)
            self.remote_public_key, self.ake.gy.__id__ = self.process_encrypted_signature(message.encrypted_signature, self.ake.aes_c, self.ake.mac_m1)
            self.send_message(SignatureMessage.new(self))
            self.dh_local_private_keys.add(DHPrivateKey())
            self.dh_remote_public_keys.add(self.ake.gy)
            self.session_id = self.ake.session_id
            self.extra_key = self.ake.extra_key
            self.ake = Null
            self.smp = SocialistMillionairesProtocol()
            self.state = OTRState.Encrypted
            if self._stop_requested:  # stopping the protocol was requested during AKE
                self._stop_requested = False
                self.stop()

    def _MH_SignatureMessage(self, message):
        if self.ake.state is AKEState.AwaitingSignature:
            message.validate_mac(key=self.ake.mac_m2p)
            self.remote_public_key, self.ake.gy.__id__ = self.process_encrypted_signature(message.encrypted_signature, self.ake.aes_cp, self.ake.mac_m1p)
            self.dh_local_private_keys.add(DHPrivateKey())
            self.dh_remote_public_keys.add(self.ake.gy)
            self.session_id = self.ake.session_id
            self.extra_key = self.ake.extra_key
            self.ake = Null
            self.smp = SocialistMillionairesProtocol()
            self.state = OTRState.Encrypted
            if self._stop_requested:  # stopping the protocol was requested during AKE
                self._stop_requested = False
                self.stop()

    def _MH_DataMessage(self, message):
        if self.state is not OTRState.Encrypted:
            error = "Received an unreadable encrypted message while unencrypted"
            self.send_message(ErrorMessage(error))
            raise EncryptedMessageError(error)
        try:
            session_key = self.session_keys[message.recipient_keyid, message.sender_keyid]
            message.validate(previous_counter=session_key.incoming_counter, mac_key=session_key.incoming_mac)
        except KeyError:
            error = "Invalid session key requested"
            self.send_message(ErrorMessage(error))
            raise EncryptedMessageError(error)
        except ValueError, e:
            error = str(e)
            self.send_message(ErrorMessage(error))
            raise EncryptedMessageError(error)
        else:
            session_key.incoming_mac.used = True
            session_key.incoming_counter = message.counter
            if message.recipient_keyid == self.dh_local_private_keys.latest.__id__:
                self.dh_local_private_keys.add(DHPrivateKey())
            if message.sender_keyid == self.dh_remote_public_keys.latest.__id__:
                self.dh_remote_public_keys.add(DHPublicKey(message.next_public_key))
            content = AESCounterCipher(session_key.incoming_key, session_key.incoming_counter).decrypt(message.encrypted_message)
            if message.content_type.startswith('text/'):
                content, sep, tlv_data = content.partition('\0')
                if sep == '\0':
                    try:
                        tlv_records = TLVRecords.decode(tlv_data)
                    except ValueError:
                        content = content + sep + tlv_data
                    else:
                        for tlv in tlv_records:
                            tlv_handler = getattr(self, '_TH_{0.__class__.__name__}'.format(tlv), Null)
                            tlv_handler(tlv)
            return content or None

    # TLV handlers

    def _TH_DisconnectTLV(self, tlv):
        self._smp_terminate(status=SMPStatus.Interrupted, reason='encryption ended', send_abort=False)
        self.remote_public_key = None
        self.session_id = None
        self.extra_key = None
        self.smp = Null
        self.state = OTRState.Finished

    @smp_message_handler(expected_state=SMPState.ExpectMessage1)
    def _TH_SMPMessage1(self, tlv):
        tlv.validate(protocol=self)
        self.smp.g2b = tlv.g2a
        self.smp.g3b = tlv.g3a
        self.smp.g2 = self.smp.g2b ** self.smp.a2
        self.smp.g3 = self.smp.g3b ** self.smp.a3
        self.smp.question = getattr(tlv, 'question', None)  # it only carries a question if it's a SMPMessage1Q TLV
        self.smp.state = SMPState.AwaitingUserSecret
        notification_center = NotificationCenter()
        notification_center.post_notification('OTRProtocolSMPVerificationDidStart', sender=self, data=NotificationData(originator='remote', question=self.smp.question))

    _TH_SMPMessage1Q = _TH_SMPMessage1

    @smp_message_handler(expected_state=SMPState.ExpectMessage2)
    def _TH_SMPMessage2(self, tlv):
        self.smp.g2b = tlv.g2a
        self.smp.g3b = tlv.g3a
        self.smp.g2 = self.smp.g2b ** self.smp.a2
        self.smp.g3 = self.smp.g3b ** self.smp.a3
        tlv.validate(protocol=self)
        self.smp.pa = self.smp.g3 ** self.smp.r                             # pa = g3^r
        self.smp.qa = self.smp.r.public_key * self.smp.g2**self.smp.secret  # qa = g1^r * g2^secret
        self.smp.pb = tlv.pa
        self.smp.qb = tlv.qa
        self.smp.pab = self.smp.pa // self.smp.pb  # Pab is always P_originator/P_responder, where originator is the one that initiated the SMP exchange
        self.smp.qab = self.smp.qa // self.smp.qb  # Qab is always Q_originator/Q_responder, where originator is the one that initiated the SMP exchange
        self.smp.ra = self.smp.qab ** self.smp.a3
        self.send_tlv(SMPMessage3.new(self))
        self.smp.state = SMPState.ExpectMessage4

    @smp_message_handler(expected_state=SMPState.ExpectMessage3)
    def _TH_SMPMessage3(self, tlv):
        self.smp.pb = tlv.pa
        self.smp.qb = tlv.qa
        self.smp.pab = self.smp.pb // self.smp.pa  # Pab is always P_originator/P_responder, where originator is the one that initiated the SMP exchange
        self.smp.qab = self.smp.qb // self.smp.qa  # Qab is always Q_originator/Q_responder, where originator is the one that initiated the SMP exchange
        tlv.validate(protocol=self)
        self.smp.ra = self.smp.qab ** self.smp.a3
        self.smp.rb = tlv.ra
        self.smp.rab = self.smp.rb ** self.smp.a3
        self.send_tlv(SMPMessage4.new(self))
        self._smp_terminate(status=SMPStatus.Success, same_secrets=self.smp.rab == self.smp.pab)

    @smp_message_handler(expected_state=SMPState.ExpectMessage4)
    def _TH_SMPMessage4(self, tlv):
        tlv.validate(protocol=self)
        self.smp.rb = tlv.ra
        self.smp.rab = self.smp.rb ** self.smp.a3
        self._smp_terminate(status=SMPStatus.Success, same_secrets=self.smp.rab == self.smp.pab)

    def _TH_SMPAbortMessage(self, tlv):
        if self.smp.ignore_next_abort:
            self.smp.ignore_next_abort = False
        else:
            self._smp_terminate(status=SMPStatus.Interrupted, reason='aborted from remote', send_abort=False)


class OTRProtocolVersion2(OTRProtocol):
    __version__ = 2

    __header__ = Struct('!HB')

    def encode_header(self, message_class):
        return self.__header__.pack(self.__version__, message_class.__type__)

    def decode_header(self, message):
        version, message_type, message_buffer = read_format(self.__header__.format, message)
        if version != self.__version__ or message_type not in EncodedMessage.types:
            raise ValueError("Not an OTR version 2 message")
        return EncodedMessage.get(message_type), message_buffer


class OTRProtocolVersion3(OTRProtocol):
    __version__ = 3

    __header__ = Struct('!HBII')

    def __init__(self, session):
        super(OTRProtocolVersion3, self).__init__(session)
        self.local_tag = max(getrandbits(32), 0x100)  # the smallest valid value is 0x100
        self.remote_tag = 0

    def encode_header(self, message_class):
        return self.__header__.pack(self.__version__, message_class.__type__, self.local_tag, self.remote_tag)

    def decode_header(self, message):
        version, message_type, sender_tag, recipient_tag, message_buffer = read_format(self.__header__.format, message)
        if version != self.__version__ or message_type not in EncodedMessage.types:
            raise ValueError("Not an OTR version 3 message")
        if sender_tag < 0x100 or 0 < recipient_tag < 0x100:
            raise IgnoreMessage
        if self.remote_tag == 0:
            self.remote_tag = sender_tag
        if recipient_tag != 0 and (self.local_tag, self.remote_tag) != (recipient_tag, sender_tag):
            raise IgnoreMessage
        return EncodedMessage.get(message_type), message_buffer

