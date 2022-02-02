#!/usr/bin/env python2
# https://github.com/JPCERTCC/MalConfScan/blob/master/utils/formbookscan.py

import re
from sys import argv, stdout
from Crypto.Hash import SHA
from struct import unpack, unpack_from, pack
from collections import OrderedDict
from formbook_decryption import FormBookDecryption

# Config pattern
CONFIG_PATTERNS = [re.compile("\x83\xc4\x0c\x6a\x14\xe8(....)\x83\xc0\x02\x50\x8d(..)\x51\xe8(....)\x83\xc4\x0c\x6a\x14\xe8(....)\x83\xc0\x02\x50\x8d(..)\x52", re.DOTALL)]

# Hashes pattern
HASHS_PATTERNS = [re.compile("\x68(.)(\x02|\x03)\x00\x00\x8d(...)\x00\x00\xe8", re.DOTALL)]

# Strings pattern
STRINGS_PATTERNS = [re.compile("\x6a\x00\x50\xc6\x85(....)\x00\xe8(....)\x83\xc4\x0c\x68(..)\x00\x00\xe8", re.DOTALL)]


class formbookConfig():
    """Parse the Formbook configuration"""

    def sha1_revert(self, digest):
        tuples = unpack("<IIIII", digest)
        output_hash = ""
        for item in tuples:
            output_hash += pack(">I", item)
        return output_hash

    def formbook_compute_sha1(self, input_buffer):
        sha1 = SHA.new()
        sha1.update(input_buffer)
        return self.sha1_revert(sha1.digest())

    def formbook_decrypt_strings(self, fb_decrypt, p_data, key, encrypted_strings):
        offset = 0
        i = 0
        while offset < len(encrypted_strings):
            str_len = ord(encrypted_strings[offset])
            offset += 1
            dec_str = fb_decrypt.decrypt_func2(encrypted_strings[offset:offset + str_len], key)
            dec_str = dec_str[:-1]  # remove '\0' character
            p_data["Encoded string " + str(i)] = dec_str
            offset += str_len
            i += 1

        return p_data

    def formbook_decrypt(self, key1, key2, config, config_size, strings_data, strings_size, url_size, hashs_data, hashs_size):
        fb_decrypt = FormBookDecryption()
        p_data = OrderedDict()

        rc4_key_one = fb_decrypt.decrypt_func1(key1, 0x14)
        rc4_key_two = fb_decrypt.decrypt_func1(key2, 0x14)
        encbuf2_s1 = fb_decrypt.decrypt_func1(hashs_data, hashs_size)
        encbuf8_s1 = fb_decrypt.decrypt_func1(config, config_size)
        encbuf9_s1 = fb_decrypt.decrypt_func1(strings_data, strings_size)

        rc4_key_1 = self.formbook_compute_sha1(encbuf8_s1)
        rc4_key_2 = self.formbook_compute_sha1(encbuf9_s1)
        rc4_key_3 = self.formbook_compute_sha1(rc4_key_two)
        encbuf2_s2 = fb_decrypt.decrypt_func2(encbuf2_s1, rc4_key_1)
        encbuf8_s2 = fb_decrypt.decrypt_func2(encbuf8_s1, rc4_key_2)

        n = 1
        for i in xrange(config_size):
            encrypted_c2c_uri = encbuf8_s2[i:i + url_size]
            encrypted_c2c_uri = fb_decrypt.decrypt_func2(encrypted_c2c_uri, rc4_key_two)
            c2c_uri = fb_decrypt.decrypt_func2(encrypted_c2c_uri, rc4_key_one)
            if "www." in c2c_uri:
                p_data["C&C URI " + str(n)] = c2c_uri
                n += 1

        encrypted_hashes_array = fb_decrypt.decrypt_func2(encbuf2_s2, rc4_key_3)
        rc4_key_pre_final = self.formbook_compute_sha1(encrypted_hashes_array)
        rc4_key_final = fb_decrypt.decrypt_func2(rc4_key_two, rc4_key_pre_final)

        p_data = self.formbook_decrypt_strings(fb_decrypt, p_data, rc4_key_final, encbuf9_s1)

        return p_data

    def calculate(self, fname):
        with open(fname) as f:
            data = f.read()

        for pattern in CONFIG_PATTERNS:
            offset = re.search(pattern, data).start()

        offset += 6
        key1_offset = unpack("=I", data[offset:offset + 4])[0] + offset + 11
        key1 = data[key1_offset:key1_offset + (0x14 * 2)]
        offset += 23
        key2_offset = unpack("=I", data[offset:offset + 4])[0] + offset + 11
        key2 = data[key2_offset:key2_offset + (0x14 * 2)]
        offset += 21
        config_size = unpack("=I", data[offset:offset + 4])[0]
        offset += 5
        config_offset = unpack("=I", data[offset:offset + 4])[0] + offset + 11
        config = data[config_offset:config_offset + (config_size * 2)]
        offset += 33
        url_size = unpack("b", data[offset])[0]

        for pattern in STRINGS_PATTERNS:
            offset = re.search(pattern, data).start()

        offset += 19
        strings_size = unpack("=I", data[offset:offset + 4])[0]
        offset += 5
        strings_offset = unpack("=I", data[offset:offset + 4])[0] + offset + 11
        strings_data = data[strings_offset:strings_offset + (strings_size * 2)]

        for pattern in HASHS_PATTERNS:
            offset = re.search(pattern, data).start()

        offset += 1
        hashs_size = unpack("=I", data[offset:offset + 4])[0]
        offset += 11
        hashs_offset = unpack("=I", data[offset:offset + 4])[0] + offset + 11
        hashs_data = data[hashs_offset:hashs_offset + (hashs_size * 2)]

        return self.formbook_decrypt(key1, key2, config, config_size, strings_data,
                                    strings_size, url_size, hashs_data, hashs_size)

    def render_text(self, outfd, data):
        outfd.write("[Config Info]\n")
        for id, param in data.items():
            outfd.write("{0:<16}: {1}\n".format(id, param))

if __name__ == "__main__":
    fc = formbookConfig()
    config_data = fc.calculate(argv[1])
    fc.render_text(stdout, config_data)
