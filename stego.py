from typing import Union
from PIL import Image


def data_to_binary(data: bytes) -> list:
    binary_strings = []
    for i in data:
        binary_strings.append(format(i, '08b'))
    return binary_strings


def modify_pixels(pixels, data: bytes):
    binary_strings = data_to_binary(data)
    data_length = len(binary_strings)
    image_data = iter(pixels)
    for i in range(data_length):
        pixels = [value for value in next(image_data)[:3] + next(image_data)[:3] + next(image_data)[:3]]
        for j in range(0, 8):
            if binary_strings[i][j] == '0' and pixels[j] % 2 != 0:
                pixels[j] -= 1
            elif binary_strings[i][j] == '1' and pixels[j] % 2 == 0:
                if pixels[j] > 0:
                    pixels[j] -= 1
                else:
                    pixels[j] += 1
        if i == data_length - 1:
            if pixels[-1] % 2 == 0:
                if pixels[-1] > 0:
                    pixels[-1] -= 1
                else:
                    pixels[-1] += 1
        else:
            if pixels[-1] % 2 != 0:
                pixels[-1] -= 1
        pixels = tuple(pixels)
        yield pixels[0:3]
        yield pixels[3:6]
        yield pixels[6:9]


def encode(data: Union[bytes, str], image_path: str, output_path: str):
    if isinstance(data, str):
        data = data.encode('utf-8')
    image = Image.open(image_path)
    new_image = image.copy()
    width = new_image.size[0]
    x, y = 0, 0
    for pixel in modify_pixels(new_image.getdata(), data):
        new_image.putpixel((x, y), pixel)
        if x == width - 1:
            x = 0
            y += 1
        else:
            x += 1
    new_image.save(output_path, 'png')


def decode(image_path: str) -> bytes:
    image = Image.open(image_path)
    data = b''
    image_data = iter(image.getdata())
    while True:
        pixels = [value for value in next(image_data)[:3] + next(image_data)[:3] + next(image_data)[:3]]
        binary_string = ''
        for i in pixels[:8]:
            if i % 2 == 0:
                binary_string += '0'
            else:
                binary_string += '1'
        data += bytes((int(binary_string, 2),))
        if pixels[-1] % 2 != 0:
            return data
