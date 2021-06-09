from PIL import Image


def GenerateData(data, bin = False):
    newData = []
    for i in data:
        newData.append(format(ord(i), '08b'))

    return newData


def ModifyPixels(pix, data):
    datalist = GenerateData(data)
    lendata = len(datalist)
    imdata = iter(pix)
    for i in range(lendata):
        pix = [value for value in imdata.__next__()[:3] + imdata.__next__()[:3] + imdata.__next__()[:3]]
        for j in range(0, 8):
            if (datalist[i][j] == '0' and pix[j] % 2 != 0):
                pix[j] -= 1

            elif (datalist[i][j] == '1' and pix[j] % 2 == 0):
                if(pix[j] != 0):
                    pix[j] -= 1

                else:
                    pix[j] += 1

        if (i == lendata - 1):
            if (pix[-1] % 2 == 0):
                if(pix[-1] != 0):
                    pix[-1] -= 1

                else:
                    pix[-1] += 1

        else:
            if (pix[-1] % 2 != 0):
                pix[-1] -= 1

        pix = tuple(pix)
        yield pix[0:3]
        yield pix[3:6]
        yield pix[6:9]


def encode_enc(newImage, data):
    width = newImage.size[0]
    (x, y) = (0, 0)
    for pixel in ModifyPixels(newImage.getdata(), data):
        newImage.putpixel((x, y), pixel)
        if (x == width - 1):
            x = 0
            y += 1

        else:
            x += 1


def Encode(imagePath, data, output):
    image = Image.open(imagePath, 'r')
    newImage = image.copy()
    encode_enc(newImage, data)
    newImage.save(output, 'PNG')


def Decode(imagePath):
    image = Image.open(imagePath, 'r')
    data = ''
    imgdata = iter(image.getdata())
    while (True):
        pixels = [value for value in imgdata.__next__()[:3] + imgdata.__next__()[:3] + imgdata.__next__()[:3]]
        binstr = ''
        for i in pixels[:8]:
            if (i % 2 == 0):
                binstr += '0'

            else:
                binstr += '1'

        data += chr(int(binstr, 2))

        if (pixels[-1] % 2 != 0):
            return data
