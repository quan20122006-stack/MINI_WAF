import trustme
print("Dang khoi tao to chuc cap phat chung chi CA")
ca = trustme.CA()

print("Dang cap chung chi SSL cho localhost")
server_cert = ca.issue_cert("localhost" , "127.0.0.1")

#Xuat ra 2 file PEM
server_cert.private_key_pem.write_to_path("key.pem")
server_cert.cert_chain_pems[0].write_to_path("cert.pem")

print("Thanh cong")