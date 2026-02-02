from PIL import Image
import binascii

class SteganoHide:
    """
    Implements LSB steganography to hide data in images.
    """
    def encode(self, image_path, data, output_path):
        image = Image.open(image_path).convert('RGB')
        pixels = image.load()

        # Convert data to binary string
        binary_data = ''.join(format(ord(i), '08b') for i in data)
        # Add a delimiter to mark the end
        binary_data += '1111111111111110'

        data_index = 0
        width, height = image.size

        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]

                if data_index < len(binary_data):
                    r = (r & ~1) | int(binary_data[data_index])
                    data_index += 1

                if data_index < len(binary_data):
                    g = (g & ~1) | int(binary_data[data_index])
                    data_index += 1

                if data_index < len(binary_data):
                    b = (b & ~1) | int(binary_data[data_index])
                    data_index += 1

                pixels[x, y] = (r, g, b)

                if data_index >= len(binary_data):
                    image.save(output_path)
                    return True
        return False

    def decode(self, image_path):
        image = Image.open(image_path).convert('RGB')
        pixels = image.load()

        binary_data = ""
        width, height = image.size

        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                binary_data += str(r & 1)
                binary_data += str(g & 1)
                binary_data += str(b & 1)

        # Split by 8 bits and convert to char
        all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
        decoded_data = ""
        for b in all_bytes:
            if b == '11111111': # Potential end delimiter start
                break
            decoded_data += chr(int(b, 2))

        return decoded_data
