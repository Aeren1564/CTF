from hashlib import sha256

def b2l(b):
    return int.from_bytes(b, 'big')

class Transcript:
    def __init__(self, label=b""):
        self.label = label
        self.messages = []

    def put(self, message):
        if isinstance(message, str):
            message = message.encode()
        elif isinstance(message, int):
            message = str(message).encode()
        elif isinstance(message, list):
            [self.put(x) for x in message]
            return
        elif not isinstance(message, bytes):
            raise TypeError("Idk ur types")
        self.messages.append(message)

    def get_challenge(self):
        combined = self.label + b''.join(self.messages)
        self.label = sha256(combined).hexdigest().encode()
        return b2l(sha256(combined).digest())

    def reset(self):
        self.messages.clear()
        self.label = b""