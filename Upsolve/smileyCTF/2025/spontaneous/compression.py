import gzip
import io
import base64
max_output_size = 10 * 1024 * 1024

def decompress(data, max_output_size=max_output_size):
    data = base64.b64decode(data.encode())
    output = bytearray()
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
        while True:
            chunk = f.read(1024)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > max_output_size:
                raise ValueError("Decompressed data exceeds limit")
    return bytes(output)