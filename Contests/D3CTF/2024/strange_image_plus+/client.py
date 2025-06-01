import json
import websocket # pip install websocket-client
import re
from PIL import Image # pip install pillow
import struct
import threading

def bytes_to_image(image_bytes, w, g):
    pixel_bytes = list(image_bytes)
    reconstructed_image = Image.new('RGB', (w, g))
    for y in range(g):
        for x in range(w):
            start = (y * w + x) * 3
            pixel = struct.unpack('BBB', bytes(pixel_bytes[start:start + 3]))
            reconstructed_image.putpixel((x, y), pixel)
    return reconstructed_image

def image_to_bytes(image):
    w, h = image.size
    pixel_bytes = []
    for y in range(h):
        for x in range(w):
            pixel = image.getpixel((x, y))
            pixel_bytes.extend(struct.pack('BBB', *pixel))
    image_bytes = bytes(pixel_bytes)
    return image_bytes

def handle_input(ws):
    while True:
        try:
            message = input()
            msg_json = json.loads(message)
            assert 'cmd' in msg_json
            assert type(msg_json['cmd']) == str
            if msg_json['cmd'] == 'exit':
                ws.close()
                break
            elif msg_json['cmd'] == 'help':
                print('get_flag: {\'cmd\': \'get_flag\', \'taps_list\': <taps_list>(list(list)), \'iv\': <iv>(bytes.hex()), \'chunk_size\': <chunk_size>(int), \'img_path\': <path_to_img>}')
                print('help: {\'cmd\': \'help\'}')
                print('exit: {\'cmd\': \'exit\'}')
            elif msg_json['cmd'] == 'get_flag':
                try:
                    img = Image.open(msg_json['img_path'])
                    assert (img.width, img.height) == (width, height)
                    del msg_json["img_path"]
                    msg_json["data"] = image_to_bytes(img).hex()
                    ws.send(json.dumps(msg_json))
                except FileNotFoundError as err:
                    print("FileNotFoundError: {}".format(err))
            else:
                raise AssertionError("CommandFormatError")
        except Exception as err:
            print("Exception: {}".format(err))

def handle_recv(ws):
    try:
        while True:
            msg = ws.recv()
            if msg.startswith('T'):
                print('Msg from server: {}'.format(msg[1:]))
            elif msg.startswith('F'):
                print('Image from server: {}'.format(msg[1:]))
                img = bytes_to_image(bytes.fromhex(msg[1:]), width, height)
                img.show()
    except websocket.WebSocketException as err:
        print(err)

def main():
    uri = 'ws://127.0.0.1:10002'
    # uri = input('input uri: ')
    print('type \'help\' to get help')
    ws = websocket.create_connection(uri)
    input_thread = threading.Thread(target=handle_input, args=(ws,), daemon=True)
    recv_thread = threading.Thread(target=handle_recv, args=(ws,), daemon=True)
    recv_thread.start()
    input_thread.start()
    recv_thread.join()
    input_thread.join()

if __name__ == '__main__':
    width, height = 72, 60
    main()
