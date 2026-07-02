"""Admin auth: password hashing (scrypt, stdlib) + TOTP (pyotp) + backup codes."""
import os, io, hashlib, hmac, base64, secrets
import pyotp


def gen_backup_codes(n=8):
    return [secrets.token_hex(5) for _ in range(n)]   # 10 hex chars each


def hash_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().encode()).hexdigest()


def hash_pw(password: str, salt: bytes = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(h).decode()


def verify_pw(password: str, stored: str) -> bool:
    try:
        s, h = stored.split("$")
        salt = base64.b64decode(s)
        calc = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(calc, base64.b64decode(h))
    except Exception:
        return False


def new_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str) -> bool:
    try:
        return pyotp.TOTP(secret).verify(str(code).strip(), valid_window=1)
    except Exception:
        return False


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="BitLocker Escrow")


def qr_svg(data: str) -> str:
    """Render an otpauth URI as an inline SVG QR (pure-python, no Pillow needed)."""
    import qrcode
    import qrcode.image.svg as svg
    qr = qrcode.QRCode(border=2, box_size=9)
    qr.add_data(data)
    qr.make(fit=True)
    buf = io.BytesIO()
    qr.make_image(image_factory=svg.SvgPathImage).save(buf)
    return buf.getvalue().decode()
