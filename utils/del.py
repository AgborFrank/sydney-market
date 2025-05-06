from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

pgp_key = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZ80xbRYJKwYBBAHaRw8BAQdA0+Po3R8N3kmQbyazO8UVNAOY88L1I0HJ+0qO
pkTnmou0HEFnYm9yIDxheXVrZnJhbmsyQGdtYWlsLmNvbT6ImQQTFgoAQRYhBCRt
cUp9hb7N4Tzb4pnq40/yPKIaBQJnzTFtAhsDBQkFo5qABQsJCAcCAiICBhUKCQgL
AgQWAgMBAh4HAheAAAoJEJnq40/yPKIalBABALA0vkfTKzgthe9e53DwWYC9CGFp
2ar5Ap9VMo+xzZi9AQDi2UNsspsIFRBZtdw24T4Pa79QIN+N0ewU1NQVbuOcDbg4
BGfNMW0SCisGAQQBl1UBBQEBB0D3jD2RYSIVuBO15TprK7oXa7Xp6OF0onVnOrQv
KF4CHQMBCAeIfgQYFgoAJhYhBCRtcUp9hb7N4Tzb4pnq40/yPKIaBQJnzTFtAhsM
BQkFo5qAAAoJEJnq40/yPKIa6uIA/ioxuQZBeiHH7BI0xl+0KU/BRLTX8F2hOtZI
PfbwI27gAQCZvXjuqBsOCEkUWysEAt/v+b6Q1knnF06vZfHb+XFoAw==
=A91x
-----END PGP PUBLIC KEY BLOCK-----"""

try:
    public_key = serialization.load_pem_public_key(
        pgp_key.encode('utf-8'),
        backend=default_backend()
    )
    print("Key loaded successfully!")
except Exception as e:
    print(f"Error: {str(e)}")