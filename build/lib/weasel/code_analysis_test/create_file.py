import tempfile

def create_temp_file():
    f = tempfile.NamedTemporaryFile(delete=False) 
    f.write(b"test")
    f.close()
