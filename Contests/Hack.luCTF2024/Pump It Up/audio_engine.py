def extract_sound_data(voc_filename):
    with open(voc_filename, 'rb') as voc_file:
        voc_file.read(26)
        return voc_file.read()[:-1]        

def create_voc_file(output_filename, sound_data_blocks):
    with open(output_filename, 'wb') as output_file:
        output_file.write(b'Creative Voice File\x1A\x1A\x00\x14\x01\x1f\x11')
        output_file.write(sound_data_blocks+b"\x00")