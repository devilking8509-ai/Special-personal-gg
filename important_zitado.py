from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
# ==========================================
# important_zitado.py mein PURANI IMPORT LINE KI JAGAH YAH PASTE KAREIN
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
# CODE END
# ==========================================

import json
key = b'Yg&tc%DEuh6%Zc^8'  # 16-byte AES key
iv = b'6oyZDr22E3ychjM%'   # 16-byte IV

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        if result.wire_type == "varint":
            result_dict[int(result.field)] = result.data
        elif result.wire_type == "string" or result.wire_type == "bytes":
            result_dict[int(result.field)] = result.data
        elif result.wire_type == "length_delimited":
            nested_data = parse_results(result.data.results)
            result_dict[int(result.field)] = nested_data
    return result_dict


def zitado_get_proto(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None
    
def encrypt_packet(plain_text,key,iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
def dec_to_hex(ask):
    ask_result = hex(ask)
    final_result = str(ask_result)[2:]
    if len(final_result) == 1:
        final_result = "0" + final_result
        return final_result
    else:
        return final_result
def encode_varint(number):
    if number < 0:
        raise ValueError("Number must be non-negative")
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes)

def create_varint_field(field_number, value):
    field_header = (field_number << 3) | 0  
    return encode_varint(field_header) + encode_varint(value)

def create_length_delimited_field(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return encode_varint(field_header) + encode_varint(len(encoded_value)) + encoded_value

def create_protobuf_packet(fields):
    packet = bytearray()
    
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = create_protobuf_packet(value)
            packet.extend(create_length_delimited_field(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(create_varint_field(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(create_length_delimited_field(field, value))
    

    return packet
