import struct
import binascii

class ParsedResult:
    def __init__(self, field, wire_type, data):
        self.field = field
        self.wire_type = wire_type
        self.data = data

class NestedData:
    def __init__(self, results):
        self.results = results

class Parser:
    def parse(self, data):
        if isinstance(data, str):
            try:
                data = binascii.unhexlify(data)
            except:
                pass 
        
        index = 0
        length = len(data)
        results = []

        while index < length:
            # Read Key (Field + WireType)
            if index >= length: break
            key, index = self._read_varint(data, index)
            wire_type_int = key & 7
            field_id = key >> 3

            if wire_type_int == 0: # Varint
                val, index = self._read_varint(data, index)
                results.append(ParsedResult(field_id, "varint", val))
            
            elif wire_type_int == 1: # 64-bit
                if index + 8 > length: break
                val = data[index:index+8]
                index += 8
                results.append(ParsedResult(field_id, "fixed64", val))
            
            elif wire_type_int == 2: # Length Delimited
                l, index = self._read_varint(data, index)
                if index + l > length: break
                val_bytes = data[index:index+l]
                index += l
                
                # Logic to detect nested vs string vs bytes
                is_nested = False
                try:
                    # Recursive check
                    sub_parser = Parser()
                    sub_res = sub_parser.parse(val_bytes)
                    # If it parsed something substantial, assume nested
                    if sub_res and len(sub_res) > 0:
                        # Extra check: if it looks like just noise, ignore
                        results.append(ParsedResult(field_id, "length_delimited", NestedData(sub_res)))
                        is_nested = True
                except:
                    pass
                
                if not is_nested:
                    try:
                        str_val = val_bytes.decode('utf-8')
                        if str_val.isprintable():
                            results.append(ParsedResult(field_id, "string", str_val))
                        else:
                            results.append(ParsedResult(field_id, "bytes", val_bytes))
                    except:
                        results.append(ParsedResult(field_id, "bytes", val_bytes))
            
            elif wire_type_int == 5: # 32-bit
                if index + 4 > length: break
                val = data[index:index+4]
                index += 4
                results.append(ParsedResult(field_id, "fixed32", val))
            
            else:
                # Skip unknown or error
                break

        return results

    def _read_varint(self, data, index):
        result = 0
        shift = 0
        while True:
            if index >= len(data):
                raise Exception("Varint read error")
            b = data[index]
            index += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result, index
            shift += 7
            