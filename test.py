import timeit
from main import AESTest, AES

test_data = 'secret datasadjasdoapjf wafj awjfwa么v哦怕v吗v到屏幕aaaaaaaaaaaaaasncnascaosvn'.encode()

# ECB
aes128_ECB = AESTest(16, AES.MODE_ECB)
def test_aes128_ECB(data):
    encrypt_data, iv = aes128_ECB.encrypt(data)
    if data != aes128_ECB.decrypt(encrypt_data, iv):
        raise ValueError("解析错误")
    pass

aes192_ECB = AESTest(24, AES.MODE_ECB)
def test_aes192_ECB(data):
    encrypt_data, iv = aes192_ECB.encrypt(data)
    if data != aes192_ECB.decrypt(encrypt_data, iv):
        raise ValueError("解析错误")
    pass

aes256_ECB = AESTest(32, AES.MODE_ECB)
def test_aes256_ECB(data):
    encrypt_data, iv = aes256_ECB.encrypt(data)
    if data != aes256_ECB.decrypt(encrypt_data, iv):
        raise ValueError("解析错误")
    pass

# OFB
aes128_OFB = AESTest(16, AES.MODE_OFB)
def test_aes128_OFB(data):
    encrypt_data, iv = aes128_OFB.encrypt(data, iv=aes128_OFB.generate_iv())
    if data != aes128_OFB.decrypt(encrypt_data, iv):
        raise ValueError("解析错误")
    pass

aes192_OFB = AESTest(24, AES.MODE_OFB)
def test_aes192_OFB(data):
    encrypt_data, iv = aes192_OFB.encrypt(data, iv=aes192_OFB.generate_iv())
    if data != aes192_OFB.decrypt(encrypt_data, iv):
        raise ValueError("解析错误")
    pass

aes256_OFB = AESTest(32, AES.MODE_OFB)
def test_aes256_OFB(data):
    encrypt_data, iv = aes256_OFB.encrypt(data, iv=aes256_OFB.generate_iv())
    if data != aes256_OFB.decrypt(encrypt_data, iv):
        raise ValueError("解析错误")
    pass

# CFB
aes128_CFB = AESTest(16, AES.MODE_CFB)
def test_aes128_CFB(data):
    encrypt_data, iv = aes128_CFB.encrypt(data, iv=aes128_CFB.generate_iv())
    if data != aes128_CFB.decrypt(encrypt_data, iv):
        raise ValueError("解析错误")
    pass

aes192_CFB = AESTest(24, AES.MODE_CFB)
def test_aes192_CFB(data):
    encrypt_data, iv = aes192_CFB.encrypt(data, iv=aes192_CFB.generate_iv())
    if data != aes192_CFB.decrypt(encrypt_data, iv):
        raise ValueError("解析错误")
    pass

aes256_CFB = AESTest(32, AES.MODE_CFB)
def test_aes256_CFB(data):
    encrypt_data, iv = aes256_CFB.encrypt(data, iv=aes256_CFB.generate_iv())
    if data != aes256_CFB.decrypt(encrypt_data, iv):
        raise ValueError("解析错误")
    pass

# CBC
aes128_CBC = AESTest(16, AES.MODE_CBC)
def test_aes128_CBC(data):
    encrypt_data, iv = aes128_CBC.encrypt(data, iv=aes128_CBC.generate_iv())
    if data != aes128_CBC.decrypt(encrypt_data, iv):
        raise ValueError("解析错误")
    pass

aes192_CBC = AESTest(24, AES.MODE_CBC)
def test_aes192_CBC(data):
    encrypt_data, iv = aes192_CBC.encrypt(data, iv=aes192_CBC.generate_iv())
    if data != aes192_CBC.decrypt(encrypt_data, iv):
        raise ValueError("解析错误")
    pass

aes256_CBC = AESTest(32, AES.MODE_CBC)
def test_aes256_CBC(data):
    encrypt_data, iv = aes256_CBC.encrypt(data, iv=aes256_CBC.generate_iv())
    if data != aes256_CBC.decrypt(encrypt_data, iv):
        raise ValueError("解析错误")
    pass

# GCM
aes128_GCM = AESTest(16, AES.MODE_GCM)
def test_aes128_GCM(data):
    encrypt_data, iv = aes128_GCM.encrypt(data, iv=aes128_GCM.generate_iv()[:12])
    if data != aes128_GCM.decrypt(encrypt_data, iv):
        raise ValueError("解析错误")
    pass

aes192_GCM = AESTest(24, AES.MODE_GCM)
def test_aes192_GCM(data):
    encrypt_data, iv = aes192_GCM.encrypt(data, iv=aes192_GCM.generate_iv()[:12])
    if data != aes192_GCM.decrypt(encrypt_data, iv):
        raise ValueError("解析错误")
    pass

aes256_GCM = AESTest(32, AES.MODE_GCM)
def test_aes256_GCM(data):
    encrypt_data, iv = aes256_GCM.encrypt(data, iv=aes256_GCM.generate_iv()[:12])
    if data != aes256_GCM.decrypt(encrypt_data, iv):
        raise ValueError("解析错误")
    pass


def test_func(func_name, args, count=100000):
    res = timeit.timeit(
        stmt=f"{func_name}({args})",
        setup=f"from __main__ import {func_name}",
        number=count
    )
    return res

if __name__ == "__main__":
    count = 100000
    # 基于同模式下，不同密钥长度对加解密性能的影响
    for mode in ["ECB", "OFB", "CFB", "CBC", "GCM"]:
        for key_size in ["128", "192", "256"]:
            func_name = f"test_aes{key_size}_{mode}"
            res = test_func(func_name, test_data)
            print(func_name, res)
