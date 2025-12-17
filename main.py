import threading
import jwt
import random
from threading import Thread
import json
import requests 
import google.protobuf
from protobuf_decoder import Parser
import json
import datetime
import datetime
from google.protobuf.json_format import MessageToJson
import my_message_pb2
import data_pb2
import base64
import logging
import re
from Pb2 import MajoRLoGinrEq_pb2 # Ye file honi chahiye folder me
import socket
from google.protobuf.timestamp_pb2 import Timestamp
import jwt_generator_pb2
import os
import binascii
import sys
import subprocess
import http.server
import socketserver
import os
import time
# ==========================================
# PASTE THIS CODE IN PLACE OF THE DELETED IMPORT
# ==========================================

class ProtoField:
    def __init__(self, field, wire_type, data):
        self.field = field
        self.wire_type = wire_type
        self.data = data

class Parser:
    def __init__(self):
        pass

    def parse(self, data):
        # Convert hex string to bytes if needed
        if isinstance(data, str):
            try:
                data = bytes.fromhex(data)
            except ValueError:
                return []
        
        results = []
        pos = 0
        length = len(data)

        while pos < length:
            try:
                # Read Key (Field ID + Wire Type)
                key, pos = self._read_varint(data, pos)
                wire_type = key & 0x07
                field_number = key >> 3

                if wire_type == 0:  # Varint
                    value, pos = self._read_varint(data, pos)
                    results.append(ProtoField(field_number, "varint", value))
                
                elif wire_type == 1:  # 64-bit
                    if pos + 8 > length: break
                    value = data[pos:pos+8]
                    pos += 8
                    results.append(ProtoField(field_number, "fixed64", value))
                
                elif wire_type == 2:  # Length Delimited (String/Bytes/Nested)
                    str_len, pos = self._read_varint(data, pos)
                    if pos + str_len > length: break
                    value = data[pos:pos+str_len]
                    pos += str_len
                    
                    # Try to recursively parse (simple check)
                    try:
                        sub_results = self.parse(value)
                        if sub_results:
                            # Create a nested object structure if needed by your script
                            class NestedNode:
                                def __init__(self, res): self.results = res
                            results.append(ProtoField(field_number, "length_delimited", NestedNode(sub_results)))
                        else:
                            results.append(ProtoField(field_number, "bytes", value))
                    except:
                        results.append(ProtoField(field_number, "bytes", value))

                elif wire_type == 5:  # 32-bit
                    if pos + 4 > length: break
                    value = data[pos:pos+4]
                    pos += 4
                    results.append(ProtoField(field_number, "fixed32", value))
                
                else:
                    # Unknown wire type, skip or break
                    break
            except Exception:
                break
        
        return results

    def _read_varint(self, data, pos):
        result = 0
        shift = 0
        while True:
            if pos >= len(data):
                raise Exception("EOF")
            byte = data[pos]
            pos += 1
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                return result, pos
            shift += 7
            if shift >= 64:
                raise Exception("Varint too long")

# ==========================================
# END OF PASTE
# ==========================================



import MajorLoginRes_pb2
from time import sleep
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import urllib3
from important_zitado import*
from byte import*

tempid = None
sent_inv = False
start_par = False
pleaseaccept = False
nameinv = "none"
idinv = 0
senthi = False
statusinfo = False
tempdata1 = None
tempdata = None
leaveee = False
leaveee1 = False
data22 = None
isroom = False
isroom2 = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
threads = []  # <--- Ye line add karni hai

def encrypt_packet(plain_text, key, iv):
    # Ensure data is bytes
    if isinstance(plain_text, str):
        data = plain_text.encode('utf-8')
    elif isinstance(plain_text, bytes):
        data = plain_text
    else:
        data = str(plain_text).encode('utf-8')

    # Convert key and iv from hex string → bytes if needed
    if isinstance(key, str):
        try:
            key = bytes.fromhex(key)
        except ValueError:
            key = key.encode('utf-8')

    if isinstance(iv, str):
        try:
            iv = bytes.fromhex(iv)
        except ValueError:
            iv = iv.encode('utf-8')

    # Create AES cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(data, AES.block_size))
    return cipher_text.hex()
    
def gethashteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['7']
def getownteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['1']

def get_player_status(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)

    if "5" not in parsed_data or "data" not in parsed_data["5"]:
        return "OFFLINE"

    json_data = parsed_data["5"]["data"]

    if "1" not in json_data or "data" not in json_data["1"]:
        return "OFFLINE"

    data = json_data["1"]["data"]

    if "3" not in data:
        return "OFFLINE"

    status_data = data["3"]

    if "data" not in status_data:
        return "OFFLINE"

    status = status_data["data"]

    if status == 1:
        return "SOLO"
    
    if status == 2:
        if "9" in data and "data" in data["9"]:
            group_count = data["9"]["data"]
            countmax1 = data["10"]["data"]
            countmax = countmax1 + 1
            return f"INSQUAD ({group_count}/{countmax})"

        return "INSQUAD"
    
    if status in [3, 5]:
        return "INGAME"
    if status == 4:
        return "IN ROOM"
    
    if status in [6, 7]:
        return "IN SOCIAL ISLAND MODE .."

    return "NOTFOUND"
def get_idroom_by_idplayer(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    idroom = data['15']["data"]
    return idroom
def get_leader(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    leader = data['8']["data"]
    return leader
def generate_random_color():
        color_list = [
    "[00FF00][b][c]",
    "[FFDD00][b][c]",
    "[3813F3][b][c]",
    "[FF0000][b][c]",
    "[0000FF][b][c]",
    "[FFA500][b][c]",
    "[DF07F8][b][c]",
    "[11EAFD][b][c]",
    "[DCE775][b][c]",
    "[A8E6CF][b][c]",
    "[7CB342][b][c]",
    "[FF0000][b][c]",
    "[FFB300][b][c]",
    "[90EE90][b][c]"
]
        random_color = random.choice(color_list)
        return  random_color

def fix_num(num):
    fixed = ""
    count = 0
    num_str = str(num)  # Convert the number to a string

    for char in num_str:
        if char.isdigit():
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed


def fix_word(num):
    fixed = ""
    count = 0
    
    for char in num:
        if char:
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed
    
def check_banned_status(player_id):
    url = f"http://mossa-api.vercel.app/check_banned?player_id={player_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data  
        else:
            return {"error": f"Failed to fetch data. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def encode_varint(number):
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80  # Set the 8th bit to 1 if the number still has extra bits.
        encoded_bytes.append(byte)
        if not number:
            break  # Stop if there are no extra bits left in the number.
    return bytes(encoded_bytes).hex()
    


def get_random_avatar():
        avatar_list = [
        '902000061', '902000060', '902000064', '902000065', '902000066', 
        '902000074', '902000075', '902000077', '902000078', '902000084', 
        '902000085', '902000087', '902000091', '902000094', '902000306','902000091','902000208','902000209','902000210','902000211','902047016','902047016','902000347'
    ]
        random_avatar = random.choice(avatar_list)
        return  random_avatar

def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data["wire_type"] = result.wire_type
        
        # Recursively parse nested messages
        if result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        
        # Handle bytes/strings properly for JSON serialization
        elif isinstance(result.data, bytes):
            try:
                # Koshish karein UTF-8 string (jaise IP address) banane ki
                field_data["data"] = result.data.decode('utf-8')
            except:
                # Agar fail ho jaye (binary data), to Hex string bana dein
                field_data["data"] = result.data.hex()
        
        # Handle other types (varint, etc.)
        else:
            field_data["data"] = result.data
            
        result_dict[result.field] = field_data
    return result_dict

def dec_to_hex(ask):
    ask_result = hex(ask)
    final_result = str(ask_result)[2:]
    if len(final_result) == 1:
        final_result = "0" + final_result
    return final_result

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def extract_jwt_from_hex(hex):
    byte_data = binascii.unhexlify(hex)
    message = jwt_generator_pb2.Garena_420()
    message.ParseFromString(byte_data)
    json_output = MessageToJson(message)
    token_data = json.loads(json_output)
    return token_data
    

def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def restart_program():
    try:
        p = psutil.Process(os.getpid())
        try:
            open_files = p.open_files()
        except Exception:
            open_files = []

        try:
            connections = psutil.net_connections()
        except Exception as e:
            print(f"[WARN] Unable to get network connections: {e}")
            connections = []

        # Safely close open file descriptors
        for handler in open_files:
            try:
                os.close(handler.fd)
            except Exception:
                pass

    except Exception as e:
        print(f"[WARN] restart_program encountered an error: {e}")

    print("[INFO] Restarting program...")
    python = sys.executable
    os.execl(python, python, *sys.argv)
    
class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.daemon = True # Auto-close fix

    def run(self):
        print(f"[START] Starting Bot ID: {self.id}")
        try:
            self.get_tok()
        except Exception as e:
            print(f"[CRASH] Bot {self.id} crashed: {e}")

    def parse_my_message(self, serialized_data):
      try:
        MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)

        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        combined_timestamp = getattr(MajorLogRes, "timestamp", 0)
        BASE64_TOKEN = getattr(MajorLogRes, "token", "")

        if isinstance(key, bytes):
            key = key.hex()
        if isinstance(iv, bytes):
            iv = iv.hex()

        self.key = key
        self.iv = iv
        print(f"Key: {self.key} | IV: {self.iv}")
        return combined_timestamp, self.key, self.iv, BASE64_TOKEN

      except Exception as e:
        # print(f"Error parsing message: {e}")
        return 0, None, None, ""
        
    def nmnmmmmn(self, data):
        key, iv = self.key, self.iv
        try:
            key = key if isinstance(key, bytes) else bytes.fromhex(key)
            iv = iv if isinstance(iv, bytes) else bytes.fromhex(iv)
            data = bytes.fromhex(data)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
            return cipher_text.hex()
        except Exception as e:
            print(f"Error in nmnmmmmn: {e}")

    def spam_room(self, idroom, idplayer):
        fields = {
        1: 78,
        2: {
            1: int(idroom),
            2: "[C][B]VNXR[FF0000]TEAM",
            4: 330,
            5: 6000,
            6: 201,
            10: int(get_random_avatar()),
            11: int(idplayer),
            12: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def send_squad(self, idplayer):
        fields = {
            1: 33,
            2: {
                1: int(idplayer),
                2: "IND",
                3: 1,
                4: 1,
                7: 330,
                8: 19459,
                9: 100,
                12: 1,
                16: 1,
                17: {
                2: 94,
                6: 11,
                8: "1.118.1",
                9: 3,
                10: 2
                },
                18: 201,
                23: {
                2: 1,
                3: 1
                },
                24: int(get_random_avatar()),
                26: {},
                28: {}
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def start_autooo(self):
        fields = {
        1: 9,
        2: {
            1: 11371687918
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def invite_skwad(self, idplayer):
        fields = {
        1: 2,
        2: {
            1: int(idplayer),
            2: "IND",
            4: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def request_skwad(self, idplayer):
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "IND",
            3: 1,
            4: 1,
            7: 330,
            8: 19459,
            9: 100,
            12: 1,
            16: 1,
            17: {
            2: 94,
            6: 11,
            8: "1.118.1",
            9: 3,
            10: 2
            },
            18: 201,
            23: {
            2: 1,
            3: 1
            },
            24: int(get_random_avatar()),
            26: {},
            28: {}
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def skwad_maker(self):
        fields = {
        1: 1,
        2: {
            2: "\u0001",
            3: 1,
            4: 1,
            5: "en",
            9: 1,
            11: 1,
            13: 1,
            14: {
            2: 5756,
            6: 11,
            8: "1.118.1",
            9: 3,
            10: 2
            },
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def changes(self, num):
        fields = {
        1: 17,
        2: {
            1: 11371687918,
            2: 1,
            3: int(num),
            4: 62,
            5: "\u001a",
            8: 5,
            13: 329
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
   
    def leave_s(self):
        fields = {
        1: 7,
        2: {
            1: 11371687918
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def leave_room(self, idroom):
        fields = {
        1: 6,
        2: {
            1: int(idroom)
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def stauts_infoo(self, idd):
        fields = {
        1: 7,
        2: {
            1: 11371687918
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
        
        
        
        
        
        
    def GenResponsMsg(self, Msg, Enc_Id):
        fields = {
        1: 1,
        2: {
        1: 12947146032,
        2: Enc_Id,
        3: 2,
        4: str(Msg),
        5: int(datetime.now().timestamp()),
        7: 2,
        9: {
        1: "mossa", 
        2: int(get_random_avatar()),
        3: 901049014,
        4: 330,
        5: int(get_random_avatar()),
        8: "GUILD|Friend",
        10: 1,
        11: random.choice([1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]),
        13: {
        1: 2,
         2: 1,
         },
         14: {
         1: 11017917409,
         2: 8,
         3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
         }
         },
         10: "IND",
         13: {
         1: "https://graph.facebook.com/v9.0/253082355523299/picture?width=160&height=160",
         2: 1,
         3: 1
         },
         14: {
         1: {
         1: random.choice([1, 4]),
         2: 1,
         3: random.randint(1, 180),
         4: 1,
         5: int(datetime.now().timestamp()),
         6: "IND"
         }
         }
         }
         }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1215000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "121500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1215000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def send_team_message(self, message_text):
        """Function to send messages in team chat"""
        fields = {
            1: 2,  # Different type of messages in the team
            2: {
                1: 3557944186,
                2: 0,  # We do not need a custom team ID.
                3: 1,  # Team message type
                4: str(message_text),
                5: int(datetime.now().timestamp()),
                9: {
                    2: int(get_random_avatar()),
                    3: 901041021,
                    4: 330,
                    10: 1,
                    11: 155
                },
                10: "en",
                13: {
                    1: "https://graph.facebook.com/v9.0/104076471965380/picture?width=160&height=160",
                    2: 1,
                    3: 1
                }
            },
            14: ""
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1315000000" + header_lenth_final + self.nmnmmmmn(packet)  # 13 instead of 12 For the team
        elif len(header_lenth_final) == 3:
            final_packet = "131500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "13150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1315000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def createpacketinfo(self, idddd):
        ida = Encrypt(idddd)
        packet = f"080112090A05{ida}1005"
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0F15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0F1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0F150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0F15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def accept_sq(self, hashteam, idplayer, ownerr):
        fields = {
        1: 4,
        2: {
            1: int(ownerr),
            3: int(idplayer),
            4: "\u0001\u0007\t\n\u0012\u0019\u001a ",
            8: 1,
            9: {
            2: 1393,
            4: "mossa",
            6: 11,
            8: "1.118.1",
            9: 3,
            10: 2
            },
            10: hashteam,
            12: 1,
            13: "en",
            16: "OR"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def info_room(self, idrooom):
        fields = {
        1: 1,
        2: {
            1: int(idrooom),
            3: {},
            4: 1,
            6: "en"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def sockf1(self, tok, online_ip, online_port, packet, key, iv):
        global socket_client
        global sent_inv
        global tempid
        global start_par
        global clients
        global pleaseaccept
        global tempdata1
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global data22
        global leaveee
        global isroom
        global isroom2
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        online_port = int(online_port)

        socket_client.connect((online_ip,online_port))
        print(f" Con port {online_port} Host {online_ip} ")
        print(tok)
        socket_client.send(bytes.fromhex(tok))
        while True:
            data2 = socket_client.recv(9999)
            print(data2)
            if "0500" in data2.hex()[0:4]:
                accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                kk = get_available_room(accept_packet)
                parsed_data = json.loads(kk)
                fark = parsed_data.get("4", {}).get("data", None)
                if fark is not None:
                    print(f"haaaaaaaaaaaaaaaaaaaaaaho {fark}")
                    if fark == 18:
                        if sent_inv:
                            accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                            print(accept_packet)
                            print(tempid)
                            aa = gethashteam(accept_packet)
                            ownerid = getownteam(accept_packet)
                            print(ownerid)
                            print(aa)
                            ss = self.accept_sq(aa, tempid, int(ownerid))
                            socket_client.send(ss)
                            sleep(1)
                            startauto = self.start_autooo()
                            socket_client.send(startauto)
                            start_par = False
                            sent_inv = False
                    if fark == 6:
                        leaveee = True
                        print("kaynaaaaaaaaaaaaaaaa")
                    if fark == 50:
                        pleaseaccept = True
                print(data2.hex())

            if "0600" in data2.hex()[0:4] and len(data2.hex()) > 700:
                    accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                    kk = get_available_room(accept_packet)
                    parsed_data = json.loads(kk)
                    print(parsed_data)
                    idinv = parsed_data["5"]["data"]["1"]["data"]
                    nameinv = parsed_data["5"]["data"]["3"]["data"]
                    senthi = True
            if "0f00" in data2.hex()[0:4]:
                packett = f'08{data2.hex().split("08", 1)[1]}'
                print(packett)
                kk = get_available_room(packett)
                parsed_data = json.loads(kk)
                
                asdj = parsed_data["2"]["data"]
                tempdata = get_player_status(packett)
                if asdj == 15:
                    if tempdata == "OFFLINE":
                        tempdata = f"The id is {tempdata}"
                    else:
                        idplayer = parsed_data["5"]["data"]["1"]["data"]["1"]["data"]
                        idplayer1 = fix_num(idplayer)
                        if tempdata == "IN ROOM":
                            idrooom = get_idroom_by_idplayer(packett)
                            idrooom1 = fix_num(idrooom)
                            
                            tempdata = f"id : {idplayer1}\nstatus : {tempdata}\nid room : {idrooom1}"
                            data22 = packett
                            print(data22)
                            
                        if "INSQUAD" in tempdata:
                            idleader = get_leader(packett)
                            idleader1 = fix_num(idleader)
                            tempdata = f"id : {idplayer1}\nstatus : {tempdata}\nleader id : {idleader1}"
                        else:
                            tempdata = f"id : {idplayer1}\nstatus : {tempdata}"
                    statusinfo = True 

                    print(data2.hex())
                    print(tempdata)
                
                    

                else:
                    pass
            if "0e00" in data2.hex()[0:4]:
                packett = f'08{data2.hex().split("08", 1)[1]}'
                print(packett)
                kk = get_available_room(packett)
                parsed_data = json.loads(kk)
                idplayer1 = fix_num(idplayer)
                asdj = parsed_data["2"]["data"]
                tempdata1 = get_player_status(packett)
                if asdj == 14:
                    nameroom = parsed_data["5"]["data"]["1"]["data"]["2"]["data"]
                    
                    maxplayer = parsed_data["5"]["data"]["1"]["data"]["7"]["data"]
                    maxplayer1 = fix_num(maxplayer)
                    nowplayer = parsed_data["5"]["data"]["1"]["data"]["6"]["data"]
                    nowplayer1 = fix_num(nowplayer)
                    tempdata1 = f"{tempdata}\nRoom name : {nameroom}\nMax player : {maxplayer1}\nLive player : {nowplayer1}"
                    print(tempdata1)
                    

                    
                
                    
            if data2 == b"":
                print("Connection closed by remote host")
                restart_program()
                break
    
    # --- CONNECT FUNCTION RESTORED ---
    def connect(self, tok, packet, key, iv, whisper_ip, whisper_port, online_ip, online_port):
        global clients
        global threads
        
        try:
            clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clients.connect((whisper_ip, whisper_port))
            clients.send(bytes.fromhex(tok))
            
            # Start sockf1 in background
            thread = threading.Thread(
                target=self.sockf1, args=(tok, online_ip, online_port, "anything", key, iv)
            )
            threads.append(thread)
            thread.start()

            # Keep Main Connection Alive
            while True:
                data = clients.recv(9999)
                if data == b"":
                    print("Connection closed by remote host")
                    break
                
                # Glori Command Support (Optional)
                if "1200" in data.hex()[0:4] and b"/glori" in data:
                    pass 

        except Exception as e:
            print(f"[ERROR] Connection lost: {e}")
    
    
        clients.connect((whisper_ip, whisper_port))
        clients.send(bytes.fromhex(tok))
        thread = threading.Thread(
            target=self.sockf1, args=(tok, online_ip, online_port, "anything", key, iv)
        )
        threads.append(thread)
        thread.start()

        while True:
            data = clients.recv(9999)

            if data == b"":
                print("Connection closed by remote host")
                break
                print(f"Received data: {data}")

            

            if "1200" in data.hex()[0:4] and b"/glori" in data:
                try:
                    # Team up and start playing and extracting the pack
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    
                    # Split the command to extract the player ID
                    command_split = re.split("/glori ", str(data))
                    if len(command_split) > 1:
                        player_id = command_split[1].split('(')[0].strip()
                        if "***" in player_id:
                            player_id = player_id.replace("***", "106")
                        
                        # Check accounts in Clan
                        if not player_id.isdigit():
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][FF0000]Enter /glori [uid_clan] 15", uid
                                )
                            )
                            continue
                        
                        print(f"The process of collecting glory has started successfully.: {uid_clan}")
                        
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B][1E90FF]🚀 After I helped, I went in and saw the clan.\n" +
                                f"🎯 The identifier: {fix_num(uid_clan)}\n" +
                                f"📊 Number of requests: 80,000 requests", uid
                            )
                        )
                        
                        # Improved function Play Join Requests
                        def send_spam_invite():
                            try:
                                for i in range(50):  # Send 8000 requests
                                    invskwad = self.request_skwad(player_id)
                                    socket_client.send(invskwad)
                                    time.sleep(0.1)
                                    if (i + 1) % 10 == 0:
                                        clients.send(
                                            self.GenResponsMsg(
                                                f"[C][B][00FF00]✅ Sent {i + 1} Request from origin 80000", uid
                                            )
                                        )
                                print(f"The process of collecting glory has started successfully: {player_id}")
                            except Exception as e:
                                print(f"Error sending join requests: {e}")
                                clients.send(
                                    self.GenResponsMsg(
                                        f"[C][B][FF0000]❌ An error occurred while sending.", uid
                                    )
                                )

                except Exception as e:
                    print(f"Error in /glori command: {e}")

    # -----------------------------------------------------------
    # PASTE THIS IN THE EMPTY SPACE
    # -----------------------------------------------------------

    # ======================================================
    # NEW DYNAMIC LOGIN SYSTEM (Fixed for Render/VPS)
    # ======================================================

    def dec_to_hex(self, ask):
        ask_result = hex(ask)
        final_result = str(ask_result)[2:]
        if len(final_result) == 1:
            final_result = "0" + final_result
            return final_result
        else:
            return final_result

    # ======================================================
    # FIXED DYNAMIC LOGIN (Datetime Conflict Solved)
    # ======================================================
    def EncRypTMajoRLoGin_Dynamic(self, open_id, access_token):
        try:
            # Local import to avoid conflict with 'from byte import *'
            import datetime as dt_fix 
            
            # Pb2 folder import
            from Pb2 import MajoRLoGinrEq_pb2
            
            major_login = MajoRLoGinrEq_pb2.MajorLogin()
            
            # Use local datetime alias
            major_login.event_time = str(dt_fix.datetime.now())[:-7]
            
            major_login.game_name = "free fire"
            major_login.platform_id = 1
            major_login.client_version = "1.118.1"
            major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
            major_login.system_hardware = "Handheld"
            major_login.telecom_operator = "Jio 4G" 
            major_login.network_type = "WIFI"
            major_login.screen_width = 1920
            major_login.screen_height = 1080
            major_login.screen_dpi = "280"
            major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
            major_login.memory = 3003
            major_login.gpu_renderer = "Adreno (TM) 640"
            major_login.gpu_version = "OpenGL ES 3.1 v1.46"
            major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
            
            # --- IP SPOOFING ---
            major_login.client_ip = "223.191.51.89" 
            # -------------------
            
            major_login.language = "en"
            major_login.open_id = open_id
            major_login.open_id_type = "4"
            major_login.device_type = "Handheld"
            memory_available = major_login.memory_available
            memory_available.version = 55
            memory_available.hidden_value = 81
            major_login.access_token = access_token
            major_login.platform_sdk_id = 1
            major_login.network_operator_a = "Jio 4G"
            major_login.network_type_a = "WIFI"
            major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf" 
            major_login.external_storage_total = 36235
            major_login.external_storage_available = 31335
            major_login.internal_storage_total = 2519
            major_login.internal_storage_available = 703
            major_login.game_disk_storage_available = 25010
            major_login.game_disk_storage_total = 26628
            major_login.external_sdcard_avail_storage = 32992
            major_login.external_sdcard_total_storage = 36235
            major_login.login_by = 3
            major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
            major_login.reg_avatar = 1
            major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
            major_login.channel_type = 3
            major_login.cpu_type = 2
            major_login.cpu_architecture = "64"
            major_login.client_version_code = "2019118695"
            major_login.graphics_api = "OpenGLES2"
            major_login.supported_astc_bitset = 16383
            major_login.login_open_id_type = 4
            major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWA0FUgsvA1snWlBaO1kFYg=="
            major_login.loading_time = 13564
            major_login.release_channel = "android"
            major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
            major_login.android_engine_init_flag = 110009
            major_login.if_push = 1
            major_login.is_vpn = 1
            major_login.origin_platform_type = "4"
            major_login.primary_platform_type = "4"
            
            string = major_login.SerializeToString()
            # Encrypt using your global function
            return encrypt_api(string.hex())
        except Exception as e:
            print(f"[ERROR] Protobuf Generation Failed: {e}")
            return None

    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = "https://client.ind.freefiremobile.com/GetLoginData"
        headers = {
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)',
            'Host': 'client.ind.freefiremobile.com',
            'Connection': 'close'
        }
        try:
            response = requests.post(url, headers=headers, data=PAYLOAD, verify=False, timeout=15)
            x = response.content.hex()
            json_result = get_available_room(x)
            parsed_data = json.loads(json_result)
            if '32' in parsed_data and '14' in parsed_data:
                whisper_address = parsed_data['32']['data']
                online_address = parsed_data['14']['data']
                online_ip = online_address[:len(online_address) - 6]
                whisper_ip = whisper_address[:len(whisper_address) - 6]
                online_port = int(online_address[len(online_address) - 5:])
                whisper_port = int(whisper_address[len(whisper_address) - 5:])
                return whisper_ip, whisper_port, online_ip, online_port
            return None, None, None, None
        except:
            return None, None, None, None

    def guest_token(self, uid, password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Connection": "close"
        }
        data = {
            "uid": f"{uid}",
            "password": f"{password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        try:
            response = requests.post(url, headers=headers, data=data, timeout=10)
            data = response.json()
            NEW_ACCESS_TOKEN = data.get('access_token')
            NEW_OPEN_ID = data.get('open_id')
            
            if not NEW_ACCESS_TOKEN: return False

            OLD_ACCESS_TOKEN = "ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a"
            OLD_OPEN_ID = "996a629dbcdb3964be6b6978f5d814db"
            time.sleep(0.2)
            return self.TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid)
        except Exception:
            return False

    def TOKEN_MAKER(self, OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        
        # Use New Dynamic Payload
        encrypted_hex_payload = self.EncRypTMajoRLoGin_Dynamic(NEW_OPEN_ID, NEW_ACCESS_TOKEN)
        
        if not encrypted_hex_payload:
            return False

        Final_Payload = bytes.fromhex(encrypted_hex_payload)
        
        URL = "https://loginbp.ggblueshark.com/MajorLogin"
        try:
            RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False, timeout=15)
            
            if RESPONSE.status_code != 200:
                print(f"[SERVER REJECT] Status: {RESPONSE.status_code} (Check IP)")
                return False

            combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
            
            if not BASE64_TOKEN:
                return False

            whisper_ip, whisper_port, online_ip, online_port = self.GET_LOGIN_DATA(BASE64_TOKEN, Final_Payload)
            self.key = key
            self.iv = iv
            return(BASE64_TOKEN, key, iv, combined_timestamp, whisper_ip, whisper_port, online_ip, online_port)
        
        except Exception as e:
            print(f"[ERROR] TOKEN_MAKER: {e}")
            return False
    
    def time_to_seconds(hours, minutes, seconds):
        return (hours * 3600) + (minutes * 60) + seconds

    def seconds_to_hex(seconds):
        return format(seconds, '04x')
    
    def extract_time_from_timestamp(timestamp):
        dt = datetime.fromtimestamp(timestamp)
        h = dt.hour
        m = dt.minute
        s = dt.second
        return h, m, s
    
    def get_tok(self):
       global g_token
       try:
        # === यहाँ हमने बदलाव किया है ===
        # पुराना कोड सीधे unpack कर रहा था, जिससे क्रैश हो रहा था
        result = self.guest_token(self.id, self.password)
        
        # अगर result False है (लॉगइन फेल), तो हम रुक जाएंगे और क्रैश नहीं होने देंगे
        if not result:
            print(f"[ERROR] Login Failed for ID: {self.id}")
            return None, None, None
            
        # अगर सब सही है, तो वैल्यूज निकाल लो
        token, key, iv, Timestamp, whisper_ip, whisper_port, online_ip, online_port = result
        # ================================

        g_token = token
        print(whisper_ip, whisper_port)

        decoded = jwt.decode(token, options={"verify_signature": False})
        account_id = decoded.get('account_id')
        encoded_acc = hex(account_id)[2:]
        time_hex = dec_to_hex(Timestamp)

        BASE64_TOKEN_ = token.encode()  # ensure bytes, not string

        head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
        length = len(encoded_acc)
        zeros = '00000000'

        if length == 9:
            zeros = '0000000'
        elif length == 8:
            zeros = '00000000'
        elif length == 10:
            zeros = '000000'
        elif length == 7:
            zeros = '000000000'
        else:
            print('Unexpected length encountered')

        final_token = f'0115{zeros}{encoded_acc}{time_hex}00000{head}' + encrypt_packet(BASE64_TOKEN_, key, iv)
        print("Final token constructed successfully.")

        # Connect only if final_token is successfully built
        self.connect(final_token, final_token, key, iv, whisper_ip, whisper_port, online_ip, online_port)
        return final_token, key, iv

       except Exception as e:
        print(f"[ERROR] get_tok failed: {e}")
        return None, None, None
        
# ==========================================
# PASTE THIS AT THE VERY BOTTOM OF YOUR FILE
# (Replace everything from 'with open...' to the end)
# ==========================================

# --- DUMMY SERVER TO KEEP RENDER HAPPY ---
def start_dummy_server():
    try:
        PORT = int(os.environ.get("PORT", 8080))
        Handler = http.server.SimpleHTTPRequestHandler
        with socketserver.TCPServer(("", PORT), Handler) as httpd:
            print(f"[SERVER] Dummy server running on port {PORT}")
            httpd.serve_forever()
    except Exception as e:
        print(f"[SERVER] Error starting dummy server: {e}")

if __name__ == "__main__":
    
    # Start Dummy Server in Background
    server_thread = threading.Thread(target=start_dummy_server)
    server_thread.daemon = True
    server_thread.start()

    # --- YAHAN TUMHARE DIYE HUE SAARE ACCOUNTS HAIN ---
    ACCOUNTS = [
        {"id": "4345046758", "pass": "EF8AF3599E8590D76EB569EAE1916D358153E6ECCA46A6A8D2E674837DFE3EEB"},
        {"id": "4345098548", "pass": "5ACD54C84D78C1D0C8F2BB01057B1A679D62945D0AC59ADCBDCA02EC93C09F89"},
        {"id": "4345097112", "pass": "CDDA11D16A2A37DAD73267A67F00956A7C3C02109BCF6AEF4A95C1E0D9FA2758"},
        {"id": "4345110250", "pass": "8786F80392F4895D3DC440C2C944153E07CD03411A55A35FC4CA0A756545937F"},
        {"id": "4345115969", "pass": "95CCC1DC0EA4492AD3021CF10172E7098D6A76E02FD440D555B6493E88F6678A"},
        {"id": "4345116942", "pass": "9E8CB0D317DAB9F9E44345F10AC67803E25835FC73938C5B7EC65012CCA90457"},
        {"id": "4345121894", "pass": "85EF626D8B9969F572A8C1232A269AAC9FED84EDC795D55A8E430EF290156BD4"},
        {"id": "4345121638", "pass": "C0E711A2D1E6A38D57D0E54F964CF95928DA8715F0CEF012521016B2D9F2F4F6"},
        {"id": "4345130594", "pass": "A79E325CEF7DC235AB4CD9653AA506FBC50D04975D6EC0BA21D07B6351F55F39"},
        # Last wala upar wale ka duplicate tha, fir bhi maine daal diya hai safety ke liye
        {"id": "4345046758", "pass": "EF8AF3599E8590D76EB569EAE1916D358153E6ECCA46A6A8D2E674837DFE3EEB"},
    ]

    print(f"[INFO] Total {len(ACCOUNTS)} Bots Launch kiye ja rahe hain...")
    
    active_bots = []

    # --- START ALL BOTS (Sab ek sath start honge) ---
    for acc in ACCOUNTS:
        try:
            # Bot ka thread banana
            bot = FF_CLIENT(acc['id'], acc['pass'])
            
            # Daemon True karne se agar main program band karoge to bot bhi band ho jayenge
            bot.daemon = True 
            
            # Bot ko start karna (Ye background me chalega)
            bot.start()
            
            # List me save karna taki track kar sakein
            active_bots.append(bot)
            
            # Thoda sa gap taki server block na kare (0.2 seconds)
            time.sleep(0.2)
            
        except Exception as e:
            print(f"[ERROR] Bot {acc['id']} start nahi ho paya: {e}")

    print("\n[SUCCESS] Sare Bots Background me Start ho chuke hain!")

    # --- KEEP ALIVE LOOP (Ye program ko band hone se rokega) ---
    try:
        while True:
            time.sleep(10) # CPU bachane ke liye sleep
            
            # Check karna ki kitne bots abhi bhi chal rahe hain
            alive_count = sum(1 for t in active_bots if t.is_alive())
            
            if alive_count > 0:
                print(f"[STATUS] Abhi {alive_count} Bots Online hain...")
            else:
                print("[ALERT] Sare bots band ho gaye hain.")
                break
                
    except KeyboardInterrupt:
        print("\n[STOP] Program band kiya ja raha hai...")
