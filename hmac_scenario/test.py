#!/usr/bin/env python3

import hashlib
import hmac

password = 'hallo'

print('pw:\t{}'.format(password))

password_enc = password.encode('utf-8')

sk_hash = hashlib.sha256(secret_key)
print('digest:\t{}'.format(sk_hash.hexdigest()))

hmac = hmac.new("harrie".encode('utf-8'), password_enc, "sha256")
print('hmac:\t{}'.format(hmac.hexdigest()))
