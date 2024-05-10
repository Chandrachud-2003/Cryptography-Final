#python3

import time
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error
from Crypto.Protocol.KDF import HKDF

from Crypto.Random import get_random_bytes
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


    # sets user passwords dictionary (to be used by the server)
    def set_server_users(self, users):
        self.server_users = users


    # builds a login request from a dictionary
    def build_login_req(self, login_req_struct):
        login_req_str = str(login_req_struct['timestamp']) 
        login_req_str += self.delimiter + login_req_struct['username']
        login_req_str += self.delimiter + login_req_struct['password'] 
        login_req_str += self.delimiter + login_req_struct['client_random']
        return login_req_str.encode(self.coding)


    # parses a login request into a dictionary
    def parse_login_req(self, login_req):

        login_req_fields = login_req.decode(self.coding).split(self.delimiter)
        login_req_struct = {}
        login_req_struct['timestamp'] = login_req_fields[0]
        login_req_struct['username'] = login_req_fields[1]
        login_req_struct['password'] = login_req_fields[2]
        login_req_struct['client_random'] = login_req_fields[3]
        return login_req_struct


    # builds a login response from a dictionary
    def build_login_res(self, login_res_struct):
        login_res_str = login_res_struct['request_hash']
        login_res_str += self.delimiter + login_res_struct['server_random']
        return login_res_str.encode(self.coding)


    # parses a login response into a dictionary
    def parse_login_res(self, login_res):
        login_res_fields = login_res.decode(self.coding).split(self.delimiter)
        login_res_struct = {}
        login_res_struct['request_hash'] = bytes.fromhex(login_res_fields[0])
        login_res_struct['server_random'] = login_res_fields[1]
        return login_res_struct


    # check correctness of a provided password
    def check_password(self, pwd, usr_struct):

        pwdhash = PBKDF2(pwd, usr_struct['salt'], len(usr_struct['pwdhash']), count=usr_struct['icount'], hmac_hash_module=SHA256)
        if pwdhash == usr_struct['pwdhash']: return True
        return False


    # handles login process (to be used by the server)
    def handle_login_server(self):

        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')

        # trying to receive a login request
        try:
            print("Trying to receive a login request")
            msg_type, msg_payload = self.mtp.receive_msg()
            # Printing the msg_type and msg_payload
            print("msg_type: ", msg_type)
            print("msg_payload: ", msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)
        
        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            # print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG a

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')

        # processing login request
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        login_req_struct = self.parse_login_req(msg_payload)

        # Extract the timestamp and convert to integer
        client_timestamp = int(login_req_struct['timestamp'])

        # Get current server time in nanoseconds
        server_time_ns = time.time_ns()

        # Define the acceptance window in nanoseconds (e.g., ±1 second)
        window_ns = 1 * 1e9 * 2  # 1 second in nanoseconds

        print("Checking if the timestamp is within the acceptable window")

        # Check if the timestamp is within the acceptable window
        if not (server_time_ns - window_ns <= client_timestamp <= server_time_ns + window_ns):
            raise SiFT_LOGIN_Error('Timestamp out of acceptable range')
        
        print("Checking if the username and password are correct")

        # checking username and password
        if login_req_struct['username'] in self.server_users:
            if not self.check_password(login_req_struct['password'], self.server_users[login_req_struct['username']]):
                raise SiFT_LOGIN_Error('Password verification failed')
        else:
            raise SiFT_LOGIN_Error('Unknown user attempted to log in')
        
        print("Building login response")

        # building login response
        login_res_struct = {}
        login_res_struct['request_hash'] = request_hash
         # Generate server_random
        server_random = get_random_bytes(16)
        login_res_struct = {
            'request_hash': request_hash.hex(),  # Convert to hex for transmission
            'server_random': server_random.hex()
        }
        msg_payload = self.build_login_res(login_res_struct)


        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # sending login response
        print("Trying to send login response")
        try:
            print("Sending login response")
            self.mtp.send_msg(self.mtp.type_login_res, msg_payload, use_temp_key = True) # Send the login response - no _etk for login response
            print("Login response sent successfully")
             # Derive session key and apply it to the MTP protocol
            client_random = bytes.fromhex(login_req_struct['client_random'])
            session_key = self.derive_session_key(client_random.hex(), server_random.hex(), request_hash.hex())
            print("Session key derived successfully")
            self.mtp.set_session_key(session_key)
            print("Session key set successfully")
            self.mtp.reset_sequence()
            print("Sequence number reset successfully")
            print("Session key set successfully")
            print("Session Key - ", session_key.hex())
            print("Server Random - ", server_random.hex())
            print("Client Random - ", client_random.hex())
            print("Request Hash - ", request_hash.hex())

        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('User ' + login_req_struct['username'] + ' logged in')
        # DEBUG 

        # Send response
        print("Sent login response")
        return login_req_struct['username'], client_random.hex(), server_random.hex(), request_hash.hex()


    # handles login process (to be used by the client)
    def handle_login_client(self, username, password):
        # Generate random values and temporary AES key
        client_random = get_random_bytes(16).hex()

        # building a login request
        login_req_struct = {}
        login_req_struct['timestamp'] = time.time_ns()
        login_req_struct['username'] = username
        login_req_struct['password'] = password
        login_req_struct['client_random'] = client_random
        msg_payload = self.build_login_req(login_req_struct)

        print("Built login request successfully")

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # trying to send login request
        print("Trying to send login request")
        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload, use_temp_key=True)
            print("Login request sent successfully")
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)

        # computing hash of sent request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        print("Computed hash of sent request payload successfully")

        print("Trying to receive login response")

        # trying to receive a login response
        try:
            # Setting the session key to the client random temporarily
            msg_type, msg_payload = self.mtp.receive_msg()
            print("Login response received successfully")
            # Printing the msg_type and msg_payload
            print("msg_type: ", msg_type)
            print("msg_payload: ", msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')

        # processing login response
        print("Parsing login response")
        login_res_struct = self.parse_login_res(msg_payload)
        print("Parsed login response successfully")

        server_random = bytes.fromhex(login_res_struct['server_random'])
        client_random = bytes.fromhex(client_random)  # Ensure client_random was stored as bytes or convert before use
        # session_key = HKDF(client_random + server_random, 32, salt=request_hash, hashmod=SHA256)
        session_key = self.derive_session_key(login_req_struct['client_random'], server_random.hex(), request_hash.hex())
        self.mtp.set_session_key(session_key)  # Apply the session key to the MTP protocol
        print("Session key set successfully")
        print("Session Key - ", session_key.hex())
        print("Server Random - ", server_random.hex())
        print("Client Random - ", client_random.hex())
        print("Request Hash - ", request_hash.hex())

        # Resetting the sequence number
        self.mtp.reset_sequence()

        print("Reset sequence number successfully")

        print("Checking if the request hash received in the login response is the same as the one computed")
        
        # checking request_hash receiveid in the login response
        if login_res_struct['request_hash'] != request_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')
        
        print("Login response verified successfully")
        
    def derive_session_key(self, client_random, server_random, request_hash):
        # Convert hex strings back to bytes
        client_random = bytes.fromhex(client_random)
        server_random = bytes.fromhex(server_random)
        request_hash = bytes.fromhex(request_hash)

        # Concatenate random values and use HKDF to derive the session key
        combined = client_random + server_random
        session_key = HKDF(combined, 32, salt=request_hash, hashmod=SHA256)
        return session_key


