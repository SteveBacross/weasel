import os

def write_sensitive_data():
    with open("secret.txt", "w") as f:
        os.chmod("secret.txt", 0o777) 
        f.write("secret data")
