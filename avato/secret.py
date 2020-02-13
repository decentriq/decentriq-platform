import chily


class Secret:
    def __init__(self, path=None):
        if path:
            with open(path, "rb") as f:
                secretB = f.read()
            secret = chily.StaticSecret.from_bytes(secretB)
            self.keypair = chily.Keypair.from_secret(secret)
        else:
            self.keypair = chily.Keypair.from_random()

    def save_secret(self, path):
        secretB = bytearray(self.keypair.secret.bytes)
        with open(path, "wb") as f:
            f.write(secretB)

    def __str__(self):
        return f"Keypair pubk={self.keypair.public_key.bytes} secret={self.keypair.secret.bytes}"
