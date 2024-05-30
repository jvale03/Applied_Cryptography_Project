from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
import datetime, re, bson, random, os

############################ Certificates ############################

def load_client_data(filename):
    with open(filename, "rb") as file:
        data = file.read()
    password = None
    (priv_key, cert, [ca_cert]) = pkcs12.load_key_and_certificates(data, password)
    return (priv_key, cert, ca_cert)

def get_certificate_public_key(cert):
    return cert.public_key()

def sign(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(public_key, signature, message):
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def load_certificate(filename):
    with open(filename, "rb") as cert_file:
        return x509.load_pem_x509_certificate(cert_file.read())

def validate_certificate_time(cert):
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise x509.verification.VerificationError("Certificate is not valid at this time")

def validate_certificate_subject(cert, attrs=[]):
    for attr in attrs:
        if cert.subject.get_attributes_for_oid(attr[0])[0].value != attr[1]:
            raise x509.verification.VerificationError("Certificate subject does not match expected value")

def validate_certificate_extensions(cert, policy=[]):
    for ext_oid, pred_func in policy:
        ext = cert.extensions.get_extension_for_oid(ext_oid).value
        if not pred_func(ext):
            raise x509.verification.VerificationError("Certificate extensions does not match expected value")

def validate_certificate_signature(cert, ca_cert):
    issuer_public_key = ca_cert.public_key()
    issuer_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        cert.signature_algorithm_parameters,
        cert.signature_hash_algorithm
    )

def validate_certificate_server(cert, ca_cert):
    subjects = [
        (x509.NameOID.COMMON_NAME, "SSI Message Relay Server"), 
        (x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "SSI MSG RELAY SERVICE"), 
        (x509.NameOID.PSEUDONYM, "MSG_SERVER")
    ]

    extensions = [
        (x509.ExtensionOID.BASIC_CONSTRAINTS, lambda e: not e.ca),
        (x509.ExtensionOID.KEY_USAGE, lambda e: e.digital_signature and e.content_commitment),
        (x509.ExtensionOID.EXTENDED_KEY_USAGE, lambda e: x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in e)
    ]

    try:
        # issuer
        if validate_certificate_ca(ca_cert):
            cert.verify_directly_issued_by(ca_cert)
        else:
            return False
        # time
        validate_certificate_time(cert)
        # subject
        validate_certificate_subject(cert, subjects)
        # extensions
        validate_certificate_extensions(cert, extensions)
        # signature
        validate_certificate_signature(cert, ca_cert)
        return True
    except:
        return False

def validate_certificate_client(cert, ca_cert):
    regex = re.compile(r'MSG_CLI(\d+)')
    id = re.match(regex, cert.subject.get_attributes_for_oid(x509.NameOID.PSEUDONYM)[0].value).group(1)
    
    subjects = [
        (x509.NameOID.COMMON_NAME, f"User {id} (SSI MSG Relay Client {id})"),
        (x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "SSI MSG RELAY SERVICE"),
        (x509.NameOID.PSEUDONYM, f"MSG_CLI{id}")
    ]

    extensions = [
        (x509.ExtensionOID.BASIC_CONSTRAINTS, lambda e: not e.ca),
        (x509.ExtensionOID.KEY_USAGE, lambda e: e.digital_signature and e.content_commitment),
        (x509.ExtensionOID.EXTENDED_KEY_USAGE, lambda e: x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in e)
    ]
    
    try:
        # issuer
        if validate_certificate_ca(ca_cert):
            cert.verify_directly_issued_by(ca_cert)
        else:
            return False
        # time
        validate_certificate_time(cert)
        # subject
        validate_certificate_subject(cert, subjects)
        # extensions
        validate_certificate_extensions(cert, extensions)
        # signature
        validate_certificate_signature(cert, ca_cert)
        return True
    except:
        return False

def validate_certificate_ca(cert):
    subjects = [
        (x509.NameOID.COMMON_NAME, "MSG RELAY SERVICE CA"),
        (x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "SSI MSG RELAY SERVICE"),
        (x509.NameOID.PSEUDONYM, "MSG_CA")
    ]

    extensions = [
        (x509.ExtensionOID.BASIC_CONSTRAINTS, lambda e: e.ca),
        (x509.ExtensionOID.KEY_USAGE, lambda e: e.key_cert_sign and e.crl_sign)
    ]

    try:
        # issuer
        cert.verify_directly_issued_by(cert)
        # time
        validate_certificate_time(cert)
        # subject
        validate_certificate_subject(cert, subjects)
        # extensions
        validate_certificate_extensions(cert, extensions)
        # signature
        validate_certificate_signature(cert, cert)
        return True
    except:
        return False

def get_pseudonym(cert):
    return cert.subject.get_attributes_for_oid(x509.NameOID.PSEUDONYM)[0].value

def serialize_certificate(cert):
    return cert.public_bytes(
        encoding = serialization.Encoding.DER
    )

def deserialize_certificate(cert_data):
    return x509.load_der_x509_certificate(cert_data)

############################ X3DH ############################

def derive_key(shared_key):
    hkdf = HKDF(
        algorithm = hashes.SHA256(),
        length = 128,
        salt = None,
        info = b"GoodProtocol",
    )
    return hkdf.derive(shared_key)

def generate_private_key():
    return X25519PrivateKey.generate()

def generate_public_key(private_key):
    return private_key.public_key()

def generate_private_OPK_bundle(n):
    return [generate_private_key() for _ in range(n)]

def generate_public_OPK_bundle(OPK_private_bundle):
    return [generate_public_key(OPK_private) for OPK_private in OPK_private_bundle]

def pick_OPK(OPK_bundle):
    if len(OPK_bundle) == 0:
        return None
    index = random.choice(range(len(OPK_bundle)))
    return OPK_bundle.pop(index)

def generate_shared_key1(IK_priv, EK_priv, IK_pub, SK_pub, OPK_pub):
    DH1 = IK_priv.exchange(SK_pub)
    DH2 = EK_priv.exchange(IK_pub)
    DH3 = EK_priv.exchange(SK_pub)
    DH4 = EK_priv.exchange(OPK_pub)
    return derive_key(DH1 + DH2 + DH3 + DH4)

def generate_shared_key2(IK_priv, SK_priv, OPK_priv, IK_pub, EK_pub):
    DH1 = SK_priv.exchange(IK_pub)
    DH2 = IK_priv.exchange(EK_pub)
    DH3 = SK_priv.exchange(EK_pub)
    DH4 = OPK_priv.exchange(EK_pub)
    return derive_key(DH1 + DH2 + DH3 + DH4)

def serialize_pub_key(key):
    return key.public_bytes(
        encoding = serialization.Encoding.DER,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_priv_key(key):
    return key.private_bytes(
        encoding = serialization.Encoding.DER,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.NoEncryption()
    )

def deserialize_pub_key(key_data):
    return serialization.load_der_public_key(key_data)

def deserialize_priv_key(key_data):
    return serialization.load_der_private_key(key_data, password=None)

def serialize_key_bundle_message(IK, SK, signature, cert, OPK_bundle):
    return bson.dumps({
        "IK": serialize_pub_key(IK),
        "SK": serialize_pub_key(SK),
        "signature": signature,
        "cert": serialize_certificate(cert),
        "OPK_bundle": [serialize_pub_key(OPK) for OPK in OPK_bundle]
    })

def deserialize_key_bundle_message(data):
    msg = bson.loads(data)
    return (
        deserialize_pub_key(msg["IK"]),
        deserialize_pub_key(msg["SK"]),
        msg["signature"],
        deserialize_certificate(msg["cert"]),
        [deserialize_pub_key(OPK) for OPK in msg["OPK_bundle"]]
    )

############################ AES_GCM ############################

def encrypt(data, password):
    salt = os.urandom(16)
    nonce = os.urandom(12)

    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 480000,
    )

    key = kdf.derive(password)
    
    algorithm = AESGCM(key)
    ct = algorithm.encrypt(nonce, data, None)

    return salt + nonce + ct

def decrypt(data, password):
    salt = data[:16]
    nonce = data[16:28]
    ct = data[28:]

    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 480000,
    )

    key = kdf.derive(password)

    algorithm = AESGCM(key)
    dec_data = algorithm.decrypt(nonce, ct, None)

    return dec_data

########################################### DH ##########################

def generate_shared_key_dh(pub, priv):
    return derive_key(priv.exchange(pub))
