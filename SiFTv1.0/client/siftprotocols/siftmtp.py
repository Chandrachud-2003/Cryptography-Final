#python3

import socket
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 0
		self.version_minor = 5
		#header ver 1.0
		self.msg_hdr_ver = b'\x01\x00'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_mac = 12
		self.size_etk = 256
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		#message sequence start from 1
		self.sequence = 1 
		self.last_received_seq = -1  # Initialize last received sequence number
		self.reserve_bytes = 	 b'\x00\x00'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket
		

	def set_session_key(self, key):
		"""
        Set the session key for AES encryption/decryption.
        This key should be derived using HKDF as previously outlined and set
        both after login on the client and server sides.
        """
		self.aes_key = key
  
	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):
		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'] = msg_hdr[i:i+2]
		return parsed_msg_hdr


	# receives n bytes from the peer socket
	def receive_bytes(self, n):

		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received


	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):
		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		# Implement proper management of the sequence number (sqn). Sequence numbers should increment with each message and must be checked to ensure messages are received in the correct order and to protect against replay attacks.

		# Validate sequence number
		if 'last_received_seq' not in dir(self):
			self.last_received_seq = -1

		received_seq = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')
		if received_seq <= self.last_received_seq:
			print(f'Received out-of-order sequence number {received_seq}, last was {self.last_received_seq}. Discarding.')
			return None  # Discard the message silently

		self.last_received_seq = received_seq

		# Ensure that the version (ver) is checked against the expected version 01 00 for all incoming messages. Current implementation does not verify if the received version matches the expected protocol version.

		expected_version = b'\x01\x00'

		if parsed_msg_hdr['ver'] != expected_version:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			print(f'Unknown message type {parsed_msg_hdr["typ"]}. Discarding.')
			return None  # Discard the message silently

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		

		try:
			# Extracting the encrypted parts
			encrypted_payload = self.receive_bytes(msg_len - self.size_msg_hdr)
			_epd, _mac, _etk = self.split_encrypted_parts(encrypted_payload)  # Split correctly based on your message format


			# AES-GCM Decryption
			print('receive_msg Decrypting message with key:', _tk.hex())
			print('receive_msg Nonce:', parsed_msg_hdr['nonce'])

			# Decrypting the AES key
			private_rsa_key = RSA.importKey(open('test_keypair.pem').read(),passphrase='crysys')
			rsa_cipher = PKCS1_OAEP.new(private_rsa_key)
			_tk = rsa_cipher.decrypt(_etk)

			aes_gcm = AES.new(_tk, AES.MODE_GCM, nonce=parsed_msg_hdr['nonce'])
			msg_body = aes_gcm.decrypt_and_verify(_epd, _mac)
		except SiFT_MTP_Error as e:
			print(f'Failed to decrypt or verify message: {str(e)}. Discarding.')
			return None  # Discard the message silently on decryption or MAC verification failure
			

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG 

		if len(msg_body) != msg_len - self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message body reveived')

		return parsed_msg_hdr['typ'], msg_body
	

	def split_encrypted_parts(self, encrypted_payload):
		"""
        Splits the encrypted payload into encrypted data, MAC, and encrypted AES key.
        Adjust indices based on your message structure and sizes.
        """
        # Sizes based on your cryptographic setup
		size_mac = 12  # MAC length in bytes for AES-GCM
		size_etk = 256  # Encrypted AES key length in bytes for RSA-OAEP with 2048-bit keys

        # Assuming the MAC is at the end followed by the encrypted AES key
		_etk = encrypted_payload[-size_etk:]  # Last 256 bytes are the RSA-encrypted AES key
		_mac = encrypted_payload[-(size_mac + size_etk):-size_etk]  # Next 12 bytes before the ETK are the MAC
		_epd = encrypted_payload[:-(size_mac + size_etk)]  # The rest is the encrypted payload

		return _epd, _mac, _etk


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload, use_temp_key=False):
		# build message
  
		# # __len__
		# msg_size = self.size_msg_hdr + len(msg_payload) + self.size_mac + self.size_etk
		# msg_hdr_len = msg_size.to_bytes(2, byteorder='big')

		# # __sqn__
		# _sqn = self.sequence.to_bytes(2,byteorder='big')

		# # ---increase sequence by 1 each---
		# self.sequence += 1

		# # __rnd__
      	# # Generate a fresh 6-byte random value for each message
		# ranbytes = get_random_bytes(6)
		# msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + _sqn + ranbytes + self.reserve_bytes

		# __sqn__
		_sqn = self.sequence.to_bytes(2,byteorder='big')

		# __rnd__
      	# Generate a fresh 6-byte random value for each message
		ranbytes = get_random_bytes(6)
		
		# MAC field
		# --- generate a fresh 32-byte random tk ---
		_tk = get_random_bytes(32)
		aes_mac = AES.new(key= _tk, mode=AES.MODE_GCM, mac_len=12, nonce=_sqn+ranbytes) # nonce is the random bytes used here
		
		# Logging the key and nonce for debugging
		print('send_msg Generated key:', _tk.hex())
		print('send_msg Nonce:', (_sqn+ranbytes).hex())

		# print
  		# enc msg payload
		_epd, _mac = aes_mac.encrypt_and_digest(msg_payload) # Encrypt and generate MAC

		# Encrypt the temporary AES key using RSA-OAEP if required (only for login request)
		_etk = b''
		if use_temp_key:
			key = RSA.importKey(open('test_pubkey.pem').read())
			_ciphr = PKCS1_OAEP.new(key)
			_etk = _ciphr.encrypt(_tk)
		
		# # encrypt tk with RSA public key
		# key = RSA.importKey(open('test_pubkey.pem').read())
		# _ciphr = PKCS1_OAEP.new(key)
		# _etk = _ciphr.encrypt(_tk)

		# __len__
  		# Message header and sequence number handling
		# Calculate the total message size
        # header (16 bytes) + encrypted payload + MAC (12 bytes) + encrypted AES key (if applicable)
		msg_size = self.size_msg_hdr + + len(_epd) + len(_mac) + len(_etk)
		msg_hdr_len = msg_size.to_bytes(2, byteorder='big')


		# ---increase sequence by 1 each---
		self.sequence += 1

		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + _sqn + ranbytes + self.reserve_bytes
  
		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('EPD (' + str(len(_epd)) + '): ')
			print(_epd.hex())
			print('MAC (' + str(len(_mac)) + '): ')
			print(_mac.hex())
			print('ETK (' + str(len(_etk)) + '): ')
			print(_etk.hex())
			print('------------------------------------------')
		# DEBUG 

		# try to send
		try:
			# Prepare full message
			self.send_bytes(msg_hdr + _epd + _mac + _etk)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
   