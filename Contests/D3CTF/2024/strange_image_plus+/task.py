import websockets
import asyncio
from image_crypto import *

def get_flag_img(text, image_size=(72, 60), font_size=4, text_color=(0, 0, 0), background_color=(255, 255, 255)):
    image = Image.new("RGB", image_size, background_color)
    font = ImageFont.truetype("font.ttf", font_size * 3)
    draw = ImageDraw.Draw(image)
    row_size = image_size[0] - font_size
    y = 0
    current_row_size = 0
    for char in text:
        char_size = draw.textbbox((0, 0), char, font)
        if current_row_size + char_size[2] > row_size:
            y += char_size[3]
            current_row_size = char_size[2]
        else:
            current_row_size += char_size[2]
    offset = image_size[1] // 2 - y // 2 - font_size - 2

    current_row_size = 0
    y = 0
    for char in text:
        char_size = draw.textbbox((0, 0), char, font)
        if current_row_size + char_size[2] > row_size:
            y += char_size[3]
            current_row_size = char_size[2]
            text_position = (font_size // 2, offset + y)
        else:
            text_position = (current_row_size, offset + y)
            current_row_size += char_size[2]
        draw.text(text_position, char, fill=text_color, font=font)

    for x in range(image_size[0]):
        for y in range(image_size[1]):
            r, g, b = image.getpixel((x, y))
            if r < 128 and g < 128 or b < 128:
                image.putpixel((x, y), (0, 0, 0))
            else:
                image.putpixel((x, y), (255, 255, 255))

    return image

async def handle_client(websocket):
    flag_img = None
    flag_img_b = b""
    await websocket.send("TThis is a server for img-enc, but the server is not open now, so u could do nothing here")
    await websocket.send("TBut if u want flag, pls send one img(108, 80) and part of the args, I'll enc xor(img, flag_img) for each char in flag and return the result")
    await websocket.send("TNote: just read the code so that you can send args correctly")
    await websocket.send("THave fun with my server! XD")
    async for message_raw in websocket:
        try:
            msg_json = json.loads(message_raw)
            if msg_json["cmd"] == "get_flag":
                chunk_size = int(msg_json["chunk_size"])
                if flag_img is None:
                    with open("flag.txt") as f:
                        flag = f.read()
                        flag = flag.replace("d3ctf{", "")
                        flag = flag.replace("}", "")
                    flag_img = get_flag_img(flag, image_size=(width, height))
                    flag_img_b = image_to_bytes(flag_img)
                    flag_img.save("flag.png")
                img_b = bytes.fromhex(msg_json["data"])
                crypto = ImageEncryption(tap_list=msg_json["taps_list"], iv=bytes.fromhex(msg_json["iv"]), chunk_size=chunk_size)
                xor_img_b = xor_bytes(flag_img_b, img_b)
                img_enc_b = crypto.encryption(xor_img_b)
                await websocket.send("TImage received")
                await websocket.send("TImage({}) encrypted:".format(json.dumps(check_chunks(xor_img_b, chunk_size))))
                await websocket.send("F{}".format(img_enc_b.hex()))
        except:
            await websocket.send("TArgsWrong")

async def main():
    server = await websockets.serve(handle_client, "127.0.0.1", 10002)
    await server.wait_closed()


width, height = 72, 60
asyncio.run(main())
