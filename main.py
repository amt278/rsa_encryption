import rsa

'''
public_key, private_key = rsa.newkeys(1024)

with open("public_key.pem", 'wb') as f:
    f.write(public_key.save_pkcs1("PEM"))


with open('private_key.pem', 'wb') as f:
    f.write(private_key.save_pkcs1('PEM'))
'''

with open('public_key.pem', 'rb') as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

with open('private_key.pem', 'rb') as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

'''
msg = 'password'

encrypted_msg = rsa.encrypt(msg.encode(), public_key)
print(encrypted_msg)

decrypted_msg = rsa.decrypt(encrypted_msg, private_key)
print(decrypted_msg.decode())
'''
#============================================================

                ''' signing msg '''

msg = "assigned message"

'''
signature = rsa.sign(msg.encode(), private_key, "SHA-256")

with open("signature", "wb") as f:
    f.write(signature)
'''

with open("signature", "rb") as f:
    signature = f.read()

print(rsa.verify(msg.encode(), signature, public_key))
