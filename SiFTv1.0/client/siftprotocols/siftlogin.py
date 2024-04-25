#python3

import time
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import pad, unpad


class SiFT_LOGIN_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_LOGIN:
    def __init__(self, mtp):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        # --------- STATE ------------
        self.mtp = mtp
        self.server_users = None 
        self.aes_key = None  # AES key for the session


    # sets user passwords dictionary (to be used by the server)
    def set_server_users(self, users):
        self.server_users = users


    # builds a login request from a dictionary
    def build_login_req(self, login_req_struct):
        # Encrypt login details with AES-GCM
        cipher = AES.new(self.aes_key, AES.MODE_GCM)
        login_req_str = f"{login_req_struct['username']}\n{login_req_struct['password']}\n{login_req_struct['client_random']}".encode(self.coding)
        ciphertext, tag = cipher.encrypt_and_digest(pad(login_req_str, AES.block_size))
        return cipher.nonce, ciphertext, tag

    # parses a login request into a dictionary
    def parse_login_req(self, nonce, ciphertext, tag):
        # Decrypt login request
        cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
            username, password, client_random = plaintext.decode(self.coding).split('\n')
            return {'username': username, 'password': password, 'client_random': client_random}
        except (ValueError, KeyError):
            raise SiFT_LOGIN_Error("Decryption failed or tampered data")

    # builds a login response from a dictionary
    def build_login_res(self, login_res_struct):
        # Response with AES-GCM
        cipher = AES.new(self.aes_key, AES.MODE_GCM)
        response_str = f"{login_res_struct['request_hash']}\n{login_res_struct['server_random']}".encode(self.coding)
        ciphertext, tag = cipher.encrypt_and_digest(pad(response_str, AES.block_size))
        return cipher.nonce, ciphertext, tag

    # parses a login response into a dictionary
    def parse_login_res(self, nonce, ciphertext, tag):
        cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
            request_hash, server_random = plaintext.decode(self.coding).split('\n')
            return {'request_hash': request_hash, 'server_random': server_random}
        except (ValueError, KeyError):
            raise SiFT_LOGIN_Error("Decryption failed or tampered data")

    # check correctness of a provided password
    def check_password(self, pwd, usr_struct):

        pwdhash = PBKDF2(pwd, usr_struct['salt'], len(usr_struct['pwdhash']), count=usr_struct['icount'], hmac_hash_module=SHA256)
        if pwdhash == usr_struct['pwdhash']: return True
        return False


    def handle_login_server(self):
        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')

        # Receive login request
        msg_type, encrypted_data = self.mtp.receive_msg()
        nonce, ciphertext, tag, encrypted_key = encrypted_data
        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')

        # Decrypt AES key first
        rsa_cipher = PKCS1_OAEP.new(self.key)
        self.aes_key = rsa_cipher.decrypt(encrypted_key)

        # Now decrypt the actual login request
        login_req_struct = self.parse_login_req(nonce, ciphertext, tag)

        # Check username and password
        user = login_req_struct['username']
        pwd = login_req_struct['password']
        if user in self.server_users:
            usr_struct = self.server_users[user]
            if not self.check_password(pwd, usr_struct):
                raise SiFT_LOGIN_Error('Password verification failed')
        else:
            raise SiFT_LOGIN_Error('Unknown user attempted to log in')

        # Prepare login response
        server_random = get_random_bytes(16).hex()
        login_res_struct = {
            'request_hash': SHA256.new(ciphertext).hexdigest(),
            'server_random': server_random
        }
        nonce, ciphertext, tag = self.build_login_res(login_res_struct)

        # Send login response
        self.mtp.send_msg(self.mtp.type_login_res, (nonce, ciphertext, tag, server_random))
        return user


    def handle_login_client(self, username, password):
        # Generate random values and temporary AES key
        client_random = get_random_bytes(16).hex()
        self.aes_key = get_random_bytes(16)

        # Encrypt AES key with server's public RSA key
        rsa_cipher = PKCS1_OAEP.new(self.key)
        encrypted_key = rsa_cipher.encrypt(self.aes_key)

        # Build and send login request
        login_req_struct = {
            'username': username,
            'password': password,
            'client_random': client_random
        }
        nonce, ciphertext, tag = self.build_login_req(login_req_struct)
        self.mtp.send_msg(self.mtp.type_login_req, (nonce, ciphertext, tag, encrypted_key))

        # Wait for response
        msg_type, encrypted_data = self.mtp.receive_msg()
        nonce, ciphertext, tag, server_random = encrypted_data
        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')

        login_res_struct = self.parse_login_res(nonce, ciphertext, tag)

        # Verify hash
        if login_res_struct['request_hash'] != SHA256.new(ciphertext).hexdigest():
            raise SiFT_LOGIN_Error('Verification of login response failed')

        # Derive final session key using HKDF
        final_key_material = client_random + server_random
        self.session_key = HKDF(final_key_material, 32, login_res_struct['request_hash'], SHA256)
        return True
    
    def check_password(self, pwd, usr_struct):
        pwdhash = PBKDF2(pwd, usr_struct['salt'], len(usr_struct['pwdhash']), count=usr_struct['icount'], hmac_hash_module=SHA256)
        return pwdhash == usr_struct['pwdhash']
    
# This implementation relies heavily on the Crypto library for encryption, decryption, key derivation, and hashing.
# It incorporates RSA encryption for the AES key exchange, AES-GCM for protecting payloads, and HKDF for deriving session keys based on shared secrets and a non-secret salt (hash of the login request).
# The handle_login_server and handle_login_client methods now manage the cryptographic operations necessary for secure key exchange and payload protection.

