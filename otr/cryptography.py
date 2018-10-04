
from __future__ import absolute_import

from abc import ABCMeta, abstractmethod, abstractproperty
from application.python.types import MarkerType
from application.system import openfile
from cryptography.exceptions import AlreadyFinalized, InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gmpy2 import invert, legendre, mul, powmod
from hashlib import sha1
from random import getrandbits
from struct import pack
from threading import local

from otr.util import MPI, bytes_to_long, long_to_bytes, pack_mpi, read_content, read_format


__all__ = ('DHGroup', 'DHGroupNumber', 'DHGroupNumberContext', 'DHPrivateKey', 'DHPublicKey', 'DHKeyPair', 'SMPPrivateKey', 'SMPPublicKey', 'SMPExponent', 'SMPHash',
           'AESCounterCipher', 'PrivateKey', 'PublicKey', 'DSAPrivateKey', 'DSAPublicKey', 'DSASignatureHashContext')


#
# Diffie-Hellman
#

class DHGroup(object):
    prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
    order = prime >> 1
    generator = 2
    key_size = prime.bit_length()


class DHGroupNumberContext(object):
    def __init__(self, modulo=DHGroup.prime):
        self.modulo = modulo

    def __enter__(self):
        self.__backup = DHGroupNumber.__local__.context
        DHGroupNumber.__local__.context = self

    def __exit__(self, exception_type, exception_value, traceback):
        DHGroupNumber.__local__.context = self.__backup


class LocalContext(local):
    def __init__(self):
        super(LocalContext, self).__init__()
        self.context = DHGroupNumberContext()


class DHGroupNumber(long, DHGroup):
    __local__ = LocalContext()

    def __new__(cls, *args, **kw):
        return long.__new__(cls, long(*args, **kw) % cls.__local__.context.modulo)

    def __add__(self, other):
        return DHGroupNumber(long(self).__add__(other))

    def __sub__(self, other):
        return DHGroupNumber(long(self).__sub__(other))

    def __mul__(self, other):
        return DHGroupNumber(mul(self, other))

    def __floordiv__(self, other):
        return DHGroupNumber(mul(self, invert(other, self.__local__.context.modulo)))

    def __pow__(self, other, modulo=None):
        return DHGroupNumber(powmod(self, other, modulo if modulo is not None else self.__local__.context.modulo))

    __div__ = __truediv__ = __floordiv__

    def __radd__(self, other):
        return DHGroupNumber(long(self).__radd__(other))

    def __rsub__(self, other):
        return DHGroupNumber(long(self).__rsub__(other))

    def __rmul__(self, other):
        return DHGroupNumber(mul(other, self))

    def __rfloordiv__(self, other):
        return DHGroupNumber(mul(other, invert(self, self.__local__.context.modulo)))

    def __rpow__(self, other):
        return DHGroupNumber(powmod(other, self, self.__local__.context.modulo))

    __rdiv__ = __rtruediv__ = __rfloordiv__

    def __divmod__(self, other):
        return self // other, DHGroupNumber(0)

    def __rdivmod__(self, other):
        return other // self, DHGroupNumber(0)

    def __abs__(self):
        return self

    def __pos__(self):
        return self

    def __neg__(self):
        return DHGroupNumber(long(self).__neg__())

    # the modulo operation can be defined but it's not very useful, as it either returns 0 or it doesn't exist (ZeroDivisionError).
    # it's more practical to inherit modulo from the integer numbers, despite it being inconsistent with the division and divmod results
    #
    # def __mod__(self, other):
    #     self // other  # this will raise ZeroDivisionError if the numbers cannot be divided. if they can, the reminder is always 0
    #     return DHGroupNumber(0)
    #
    # def __rmod__(self, other):
    #     other // self  # this will raise ZeroDivisionError if the numbers cannot be divided. if they can, the reminder is always 0
    #     return DHGroupNumber(0)


# make the DHGroup generator be a group member
DHGroup.generator = DHGroupNumber(DHGroup.generator)


class DHPrivateKey(DHGroupNumber):
    def __new__(cls, bits=320):
        instance = super(DHPrivateKey, cls).__new__(cls, getrandbits(bits))
        instance.public_key = DHPublicKey(powmod(cls.generator, instance, cls.prime))
        instance.__id__ = None
        return instance


class DHPublicKey(DHGroupNumber):
    def __new__(cls, value):
        if not 2 <= value <= cls.prime - 2 or legendre(value, cls.prime) != 1:
            raise ValueError('invalid DH public key')
        instance = super(DHPublicKey, cls).__new__(cls, value)
        instance.__id__ = None
        return instance

    @classmethod
    def is_valid(cls, number):
        return 2 <= number <= cls.prime - 2 and legendre(number, cls.prime) == 1


class DHKeyPair(object):
    """The pairing between a DH private key and a foreign DH public key"""

    __slots__ = 'private_key', 'public_key'

    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

    def __repr__(self):
        return "{0.__class__.__name__}(private_key={0.private_key!r}, public_key={0.public_key!r})".format(self)

    @property
    def id(self):
        return self.private_key.__id__, self.public_key.__id__


class SMPPrivateKey(DHGroupNumber):
    def __new__(cls, generator=DHGroup.generator):
        instance = super(SMPPrivateKey, cls).__new__(cls, getrandbits(DHGroup.key_size))
        instance.public_key = SMPPublicKey(powmod(generator, instance, cls.prime))
        return instance


class SMPPublicKey(DHGroupNumber):
    def __new__(cls, value):
        if not 2 <= value <= cls.prime - 2 or legendre(value, cls.prime) != 1:
            raise ValueError('invalid SMP public key')
        return super(SMPPublicKey, cls).__new__(cls, value)


class SMPExponent(DHGroupNumber):
    def __new__(cls, value):
        if not 1 <= value < cls.order:
            raise ValueError('invalid SMP exponent')
        return super(SMPExponent, cls).__new__(cls, value)


class SMPHash(long):
    def __new__(cls, value):
        if not 1 <= value.bit_length() <= 256:
            raise ValueError('invalid SMP hash')
        return super(SMPHash, cls).__new__(cls, value)


#
# Ciphers
#

class AESCounterCipher(object):
    __backend__ = default_backend()

    def __init__(self, key, counter=0):
        self._cipher = Cipher(algorithms.AES(key), modes.CTR(long_to_bytes(counter << 64, 16)), self.__backend__)

    def encrypt(self, data):
        encryptor = self._cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def decrypt(self, data):
        decryptor = self._cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()


#
# User Keys
#

class KeyType(object):
    __metaclass__ = MarkerType


class DSAKey(KeyType):
    name = 'dsa'
    code = 0
    private_key_type = dsa.DSAPrivateKey
    public_key_type = dsa.DSAPublicKey


class PrivateKeyType(ABCMeta):
    __classes__ = []
    __mapping__ = {}
    __type__ = None

    def __init__(cls, name, bases, dictionary):
        super(PrivateKeyType, cls).__init__(name, bases, dictionary)
        if cls.__type__ is not None:
            cls.__classes__.append(cls)
            cls.__mapping__[cls.__type__.name] = cls
            cls.__mapping__[cls.__type__.code] = cls

    @classmethod
    def with_name(mcls, name):
        return mcls.__mapping__[name]

    @classmethod
    def with_code(mcls, code):
        return mcls.__mapping__[code]

    @classmethod
    def new(mcls, key):
        for cls in mcls.__classes__:
            if isinstance(key, cls.__type__.private_key_type):
                return cls(key)
        else:
            raise TypeError('unsupported key type: {0!r}'.format(key))


class PublicKeyType(ABCMeta):
    __classes__ = []
    __mapping__ = {}
    __type__ = None

    def __init__(cls, name, bases, dictionary):
        super(PublicKeyType, cls).__init__(name, bases, dictionary)
        if cls.__type__ is not None:
            cls.__classes__.append(cls)
            cls.__mapping__[cls.__type__.name] = cls
            cls.__mapping__[cls.__type__.code] = cls

    @classmethod
    def with_name(mcls, name):
        return mcls.__mapping__[name]

    @classmethod
    def with_code(mcls, code):
        return mcls.__mapping__[code]

    @classmethod
    def new(mcls, key):
        for cls in mcls.__classes__:
            if isinstance(key, cls.__type__.public_key_type):
                return cls(key)
        else:
            raise TypeError('unsupported key type: {0!r}'.format(key))


class PrivateKey(object):
    __metaclass__ = PrivateKeyType

    __backend__ = default_backend()

    __type__ = None

    def __init__(self, key):
        if not isinstance(key, self.__type__.private_key_type):
            raise TypeError('Mismatching key type')
        self._key = key

    @property
    def key_size(self):
        return self._key.key_size

    @property
    def private_numbers(self):
        return self._key.private_numbers()

    @property
    def parameters(self):
        return self._key.parameters()

    @abstractproperty
    def public_key(self):
        raise NotImplementedError

    @abstractmethod
    def generate(cls):
        raise NotImplementedError

    @abstractmethod
    def sign(self, data, hash_context):
        raise NotImplementedError

    @classmethod
    def load(cls, path):
        with openfile(path, 'rb') as key_file:
            key = serialization.load_pem_private_key(key_file.read(), password=None, backend=cls.__backend__)
        return PrivateKey.new(key) if cls.__type__ is None else cls(key)

    def save(self, path):
        content = self._key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        with openfile(path, 'wb', permissions=0600) as key_file:
            key_file.write(content)


class PublicKey(object):
    __metaclass__ = PublicKeyType

    __backend__ = default_backend()

    __type__ = None

    def __init__(self, key):
        if not isinstance(key, self.__type__.public_key_type):
            raise TypeError('Mismatching key type')
        self._key = key

    @property
    def key_size(self):
        return self._key.key_size

    @property
    def public_numbers(self):
        return self._key.public_numbers()

    @property
    def parameters(self):
        return self._key.parameters()

    @property
    def fingerprint(self):
        return sha1(self._encode_numbers() if self.__type__.code == 0 else self.encode()).digest()  # yay for exceptions

    @abstractmethod
    def verify(self, signature, data, hash_context):
        raise NotImplementedError

    @abstractmethod
    def _encode_numbers(self):
        raise NotImplementedError

    @abstractmethod
    def _decode_numbers(cls, encoded_numbers):
        raise NotImplementedError

    def encode(self):
        return pack('!H', self.__type__.code) + self._encode_numbers()

    @classmethod
    def decode(cls, buffer):
        code, encoded_numbers = read_format('!H', buffer)
        if cls.__type__ is not None and cls.__type__.code != code:
            raise TypeError("PublicKey type does not match")
        key_class = PublicKey.with_code(code)
        return key_class(key_class._decode_numbers(encoded_numbers))


class DSAPrivateKey(PrivateKey):
    __type__ = DSAKey

    @property
    def public_key(self):
        return DSAPublicKey(self._key.public_key())

    @classmethod
    def generate(cls):
        return cls(dsa.generate_private_key(1024, cls.__backend__))  # OTR requires that the DSA q parameter is 160 bits, which forces us to use 1024 bit keys (which are not secure)

    def sign(self, data, hash_context):
        if not isinstance(hash_context, hashes.HashContext):
            raise TypeError("hash_context must be an instance of hashes.HashContext.")
        hash_context.update(data)
        digest = hash_context.finalize()
        r, s = decode_dss_signature(self._key.sign(digest, Prehashed(SHA256HMAC160())))
        # return long_to_bytes(r, 20) + long_to_bytes(s, 20)
        size = self.private_numbers.public_numbers.parameter_numbers.q.bit_length() // 8
        return long_to_bytes(r, size) + long_to_bytes(s, size)


class DSAPublicKey(PublicKey):
    __type__ = DSAKey

    def verify(self, signature, data, hash_context):
        if not isinstance(hash_context, hashes.HashContext):
            raise TypeError("hash_context must be an instance of hashes.HashContext.")
        size = self.public_numbers.parameter_numbers.q.bit_length() // 8
        r, s = (bytes_to_long(value) for value in read_content(signature, '{0}s{0}s'.format(size)))
        # r, s = (bytes_to_long(value) for value in read_content(signature, '20s20s'))
        hash_context.update(data)
        digest = hash_context.finalize()
        try:
            self._key.verify(encode_dss_signature(r, s), digest, Prehashed(SHA256HMAC160()))
        except InvalidSignature:
            raise ValueError("invalid signature")

    def _encode_numbers(self):
        public_numbers = self.public_numbers
        parameter_numbers = public_numbers.parameter_numbers
        return pack_mpi(parameter_numbers.p) + pack_mpi(parameter_numbers.q) + pack_mpi(parameter_numbers.g) + pack_mpi(public_numbers.y)

    @classmethod
    def _decode_numbers(cls, encoded_numbers):
        p, q, g, y = read_content(encoded_numbers, MPI, MPI, MPI, MPI)
        public_numbers = dsa.DSAPublicNumbers(y, dsa.DSAParameterNumbers(p, q, g))
        return public_numbers.public_key(cls.__backend__)


class SHA256HMAC160(hashes.SHA256):
    # This is not a real hash. It's only meant to be used with Prehashed()
    # to match the size of the digest generated by DSASignatureHashContext.
    name = 'sha256-hmac-160'
    digest_size = 20


class DSASignatureHashContext(hashes.HashContext):
    def __init__(self, mac_key, dsa_key, ctx=None):
        self._mac_key = mac_key
        self._dsa_key = dsa_key
        self._backend = dsa_key.__backend__
        if ctx is None:
            self._ctx = self._backend.create_hmac_ctx(mac_key, self.algorithm)
        else:
            self._ctx = ctx

    @property
    def algorithm(self):
        return hashes.SHA256()

    def update(self, data):
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized.")
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")
        self._ctx.update(data)

    def copy(self):
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized.")
        return DSASignatureHashContext(self._mac_key, dsa_key=self._dsa_key, ctx=self._ctx.copy())

    def finalize(self):
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized.")
        digest = self._ctx.finalize()
        self._ctx = None
        q = self._dsa_key.parameters.parameter_numbers().q
        # We need this for compatibility with libotr which doesn't truncate its digest to the leftmost q.bit_length() bits
        # when the digest is longer than that as per the DSA specification (see FIPS 186-4, 4.2 & 4.6). Passing digest mod q
        # is the same as passing it unmodified, but this way we avoid the cryptography library truncating the digest as per
        # the specification, which would result in the signature verification failing.
        if self.algorithm.digest_size * 8 > q.bit_length():
            digest = long_to_bytes(bytes_to_long(digest) % q, (q.bit_length() + 7) // 8)
        return digest

