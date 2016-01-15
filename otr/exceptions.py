
class IgnoreMessage(Exception): pass
class UnencryptedMessage(Exception): pass


class OTRError(StandardError): pass
class OTRFinishedError(OTRError): pass
class EncryptedMessageError(OTRError): pass
