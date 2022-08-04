from typing import Literal, Union
import pyotp # type: ignore
import qrcode # type: ignore
import io
import base64

class Utilities:
    sc_types = ["base32", "hex"]
    otp_types = ["totp", "hotp"]

    def generate_secret_key(
        self, 
        sc_type: Union[Literal["base32"], Literal["hex"]] = "base32",
    ) -> str:
        """
        This function allows you to generate new secret key using base32 or hex.
        """

        if sc_type not in self.sc_types:
            raise ValueError(f'{sc_type=} must be in {self.sc_types}')

        if sc_type == "base32":
            return pyotp.random_base32()

        if sc_type == "hex":
            return pyotp.random_hex()


    def generate_otp_uri(
        self,
        name: str,
        issuer_name: str,
        secret_key: str,
        o_type: Union[Literal["totp"], Literal["hotp"]] = "totp",
    ) -> str:
        """
        This function allows you to get otp uri which can be used to generate QR code.
        """
        if not name:
            raise ValueError(f'{name=} should not be empty or None')

        if not issuer_name:
            raise ValueError(f'{issuer_name=} should not be empty or None')

        if not secret_key:
            raise ValueError(f'{secret_key=} should not be empty or None')

        if not self.is_base_32(secret_key) and not self.is_hex(secret_key):
            raise ValueError(f'{secret_key=} should be in base32 or hex format')

        if o_type not in self.otp_types:
            raise ValueError(f'{o_type=} must be in {self.otp_types}')

        qr_uri = None
        if o_type == "totp":
            qr_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(name=name, issuer_name=issuer_name)


        if o_type == "hotp":
            qr_uri = pyotp.hotp.HOTP(secret_key).provisioning_uri(name=name, issuer_name=issuer_name)
        
        return qr_uri


    def generate_qr_code(
        self,
        qr_uri: str,
    ) -> bytes:
        """
        This function allows you to generate QR code in bytes.
        """
        if not qr_uri:
            raise ValueError(f'{qr_uri=} should not be empty or None')

        if not self.is_valid_pyotp_uri(qr_uri):
            raise ValueError(f'{qr_uri=} is not valid uri')
        
        qr_code = qrcode.make(qr_uri)

        qr_array = io.BytesIO()
        qr_code.save(qr_array, format=qr_code.format)
        
        return qr_array.getvalue()


    def generate_qr_code_base_64(
        self,
        qr_uri: str,
    ) -> str:
        """
        This function allows you to generate QR code in a string bytes that can be easily displayed.
        """
        if not qr_uri:
            raise ValueError(f'{qr_uri=} should not be empty or None')

        if not self.is_valid_pyotp_uri(qr_uri):
            raise ValueError(f'{qr_uri=} is not valid uri')

        b_qr_code = self.generate_qr_code(qr_uri)

        qr_code = base64.b64encode(b_qr_code)
        return str(qr_code)

    
    def is_base_32(self, text: str):
        return len(text) % 8 == 0

    
    def is_base_64(self, text: str):
        return base64.b64encode(base64.b64decode(text))


    def is_hex(self, text: str):
        try:
            int(text, 16)
        except:
            return False
            
        return True


    def is_valid_pyotp_uri(self, text: str):
        try:
            pyotp.parse_uri(text)
        except:
            return False
            
        return True