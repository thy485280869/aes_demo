# -*- coding: utf-8 -*-
# 使用3.x版本的python
# pip3 install pycryptodome
# 在windows下，注意需要将crypto目录，小写的c修改成C，
# 否则会找不到库文件

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# # padding算法，原理就是按照16字节对齐
# BS = 16
# pad = lambda s: s + (BS - len(s) % BS) * chr(0)
# unpad = lambda s : s[0:-ord(s[-1])]

# 生成加解密的key：参数为密钥长度，128bit为16字节，所以传入16  192则传入24
# 实例化加密套件，使用CBC模式
# key = get_random_bytes(24)

# IV must be 16 bytes long
# iv=b'68b329da9893e340'
# 选用CBC模式加密 如果想传入iv，可直接传入iv 或者以 iv=xxx的方式传入 注意：传入的值长度必须为16字节



class AESTest(object):
    def __init__(self, key_size=24, mode=AES.MODE_CBC, pad_style='pkcs7'):
        """
        :param key_size: 密钥长度
        :param mode: 工作模式
        :param pad_style: 填充方式。默认即可
        :param iv: iv变量。如果传入，长度必须为16字节，且为bytes类型. 如果不传但模式又需要，则会默认生成
                gcm模式下传入12字节长度
        """
        if key_size in (16, 24, 32):
            self.key = get_random_bytes(key_size)
        elif key_size in (128, 192, 256):
            self.key = get_random_bytes(int(key_size/8))
        else:
            raise ValueError("key_size is error")

        if mode in (1, 2, 3, 5, 11):
            self.mode = mode
        else:
            raise ValueError("mode error")

        if pad_style not in ('pkcs7', 'x923', 'iso7816'):
            """AES模块只支持这三种，默认即可"""
            raise ValueError("Unknown padding style")
        else:
            self.pad_style = pad_style

    def encrypt(self, data, iv=None):
        if not isinstance(data, bytes):
            raise ValueError("data must be bytes")
        data = base64.b64encode(data)
        if iv is None:
            cipher = AES.new(self.key, self.mode)
        else:
            cipher = AES.new(self.key, self.mode, iv)
        data = pad(data, AES.block_size, style=self.pad_style)
        return cipher.encrypt(data), iv

    def decrypt(self, encrypt_data, iv=None):
        if not isinstance(encrypt_data, bytes):
            raise ValueError("data must be bytes")
        if iv == None:
            cipher = AES.new(self.key, self.mode)
        else:
            cipher = AES.new(self.key, self.mode, iv)
        data = unpad(cipher.decrypt(encrypt_data), AES.block_size, style=self.pad_style)
        return base64.b64decode(data)

    def generate_iv(self):
        return get_random_bytes(AES.block_size)


if __name__ == "__main__":

    data = 'secret datasadjasdoapjf wafj awjfwa么v哦怕v吗v到屏幕'
    print("待加密数据：", data)
    t192 = AESTest(192, AES.MODE_CBC)
    encrypt_data, v1 = t192.encrypt(data.encode('utf-8'), iv=t192.generate_iv())
    print("加密后为：", encrypt_data)
    data = t192.decrypt(encrypt_data, v1)
    print("解密后为：", data.decode('utf-8'))

