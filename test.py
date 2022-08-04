from utilities import Utilities
import pyotp

class Test:
    utils = Utilities()


    def test_invalid_generate_secret_key(self):
        try:
            self.utils.generate_secret_key(sc_type="base33")
        except ValueError:
            pass
        except Exception as e:
            assert False, str(e)


    def test_correct_generate_secret_key(self):
        try:
            # base 32 parameter
            default_sc = self.utils.generate_secret_key()
            assert default_sc is not None
            assert type(default_sc) == str
            assert self.utils.is_base_32(default_sc)

            # base 32 parameter
            base32_sc = self.utils.generate_secret_key(sc_type="base32")
            assert base32_sc is not None
            assert type(base32_sc) == str
            assert self.utils.is_base_32(base32_sc)

            # hex parameter
            hex_sc = self.utils.generate_secret_key(sc_type="hex")
            assert hex_sc is not None
            assert type(hex_sc) == str
            assert self.utils.is_hex(hex_sc)
        except Exception as e:
            assert False, str(e)


    def test_invalid_generate_otp_uri(self):
        # name is None
        try:
            self.utils.generate_otp_uri(name=None, issuer_name="Test Issuer Name", secret_key=self.utils.generate_secret_key())
        except ValueError:
            pass
        except Exception as e:
            assert False, str(e)

        # name is Empty
        try:
            self.utils.generate_otp_uri(name="", issuer_name="Test Issuer Name", secret_key=self.utils.generate_secret_key())
        except ValueError:
            pass
        except Exception as e:
            assert False, str(e)

        # issuer_name is None
        try:
            self.utils.generate_otp_uri(name="Test Name", issuer_name=None, secret_key=self.utils.generate_secret_key())
        except ValueError:
            pass
        except Exception as e:
            assert False, str(e)

        # issuer_name is empty
        try:
            self.utils.generate_otp_uri(name="Test Name", issuer_name="", secret_key=self.utils.generate_secret_key())
        except ValueError:
            pass
        except Exception as e:
            assert False, str(e)

        # secret_key is None
        try:
            self.utils.generate_otp_uri(name="Test Name", issuer_name="Test Issuer Name", secret_key=None)
        except ValueError:
            pass
        except Exception as e:
            assert False, str(e)

        # secret_key is empty
        try:
            self.utils.generate_otp_uri(name="Test Name", issuer_name="Test Issuer Name", secret_key="")
        except ValueError:
            pass
        except Exception as e:
            assert False, str(e)

        # secret_key is not base 32 or hex
        try:
            self.utils.generate_otp_uri(name="Test Name", issuer_name="Test Issuer Name", secret_key="838383sjjsjs")
        except ValueError:
            pass
        except Exception as e:
            assert False, str(e)

        # o_type is not valid
        try:
            self.utils.generate_otp_uri(name="Test Name", issuer_name="Test Issuer Name", secret_key=self.utils.generate_secret_key(), o_type="invalid")
        except ValueError:
            pass
        except Exception as e:
            assert False, str(e)


    def test_correct_generate_otp_uri(self):
        try:
            # default totp
            default_otp_uri = self.utils.generate_otp_uri(
                name="Test Name",
                issuer_name="Test Issuer Name",
                secret_key=self.utils.generate_secret_key(),
            )
            assert default_otp_uri is not None
            assert type(default_otp_uri) == str
            assert self.utils.is_valid_pyotp_uri(default_otp_uri)
            assert pyotp.parse_uri(default_otp_uri).__class__ == pyotp.TOTP

            # totp
            totp_uri = self.utils.generate_otp_uri(
                name="Test Name",
                issuer_name="Test Issuer Name",
                secret_key=self.utils.generate_secret_key(),
                o_type="totp"
            )
            assert totp_uri is not None
            assert type(totp_uri) == str
            assert self.utils.is_valid_pyotp_uri(totp_uri)
            assert pyotp.parse_uri(totp_uri).__class__ == pyotp.TOTP

            # hotp
            hotp_uri = self.utils.generate_otp_uri(
                name="Test Name",
                issuer_name="Test Issuer Name",
                secret_key=self.utils.generate_secret_key(),
                o_type="hotp"
            )
            assert hotp_uri is not None
            assert type(hotp_uri) == str
            assert self.utils.is_valid_pyotp_uri(hotp_uri)
            assert pyotp.parse_uri(hotp_uri).__class__ == pyotp.HOTP
        except Exception as e:
            assert False, str(e)


    def test_invalid_generate_qr_code(self):
        # qr uri is None
        try:
            self.utils.generate_qr_code(qr_uri=None)
        except ValueError:
            pass
        except Exception as e:
            assert False, str(e)

        # qr uri is empty
        try:
            self.utils.generate_qr_code(qr_uri="")
        except ValueError:
            pass
        except Exception as e:
            assert False, str(e)

        # qr uri is invalid
        try:
            self.utils.generate_qr_code(qr_uri="invalid://pyotp//")
        except ValueError:
            pass
        except Exception as e:
            assert False, str(e)


    def test_correct_generate_qr_code(self):
        try:
            # default totp
            otp_uri = self.utils.generate_otp_uri(
                name="Test Name",
                issuer_name="Test Issuer Name",
                secret_key=self.utils.generate_secret_key(),
            )
            qr_code = self.utils.generate_qr_code(qr_uri=otp_uri)
            assert qr_code is not None
            assert type(qr_code) == bytes
        except Exception as e:
            assert False, str(e)


    def test_invalid_generate_qr_code_base_64(self):
        # qr uri is None
        try:
            self.utils.generate_qr_code_base_64(qr_uri=None)
        except ValueError:
            pass
        except Exception as e:
            assert False, str(e)

        # qr uri is empty
        try:
            self.utils.generate_qr_code_base_64(qr_uri="")
        except ValueError:
            pass
        except Exception as e:
            assert False, str(e)

        # qr uri is invalid
        try:
            self.utils.generate_qr_code_base_64(qr_uri="invalid://pyotp//")
        except ValueError:
            pass
        except Exception as e:
            assert False, str(e)


    def test_correct_generate_qr_code_base_64(self):
        try:
            # default totp
            otp_uri = self.utils.generate_otp_uri(
                name="Test Name",
                issuer_name="Test Issuer Name",
                secret_key=self.utils.generate_secret_key(),
            )
            qr_code = self.utils.generate_qr_code_base_64(qr_uri=otp_uri)
            assert qr_code is not None
            assert type(qr_code) == str
            assert self.utils.is_base_64(qr_code)
        except Exception as e:
            assert False, str(e)