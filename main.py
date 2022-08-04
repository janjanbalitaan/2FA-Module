from utilities import Utilities

utils = Utilities()

secret_key = utils.generate_secret_key()
otp_uri = utils.generate_otp_uri(name="Test OTP", issuer_name="Test Issuer", secret_key=secret_key)
qr_code = utils.generate_qr_code_base_64(qr_uri=otp_uri)

print(qr_code)

