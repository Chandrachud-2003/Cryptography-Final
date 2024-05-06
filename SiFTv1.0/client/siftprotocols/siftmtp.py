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

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

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


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		# build message
		# __len__
		msg_size = self.size_msg_hdr + len(msg_payload) + self.size_mac + self.size_etk
		msg_hdr_len = msg_size.to_bytes(2, byteorder='big')
		# __sqn__
		_sqn = self.sequence.to_bytes(2,byteorder='big')
		# ---increase sequence by 1 each---
		self.sequence += 1
		# __rnd__
		ranbytes = get_random_bytes(6)
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + _sqn + ranbytes + self.reserve_bytes
		# MAC field
		# --- generate a fresh 32-byte random tk ---
		_tk = get_random_bytes(32)
		aes_mac = AES.new(key= _tk, mode=AES.MODE_GCM, mac_len=12, nonce=_sqn+ranbytes)
  		# enc msg payload
		_epd, _mac = aes_mac.encrypt_and_digest(msg_payload)
		# encrypt tk with RSA public key
		key = RSA.importKey(open('test_pubkey.pem').read())
		_ciphr = PKCS1_OAEP.new(key)
		_etk = _ciphr.encrypt(_tk)
  
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
			self.send_bytes(msg_hdr + _epd + _mac + _etk)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
   
   