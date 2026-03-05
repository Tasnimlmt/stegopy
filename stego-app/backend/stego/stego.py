"""
Advanced Steganography Engine
Features: Deniable Stego, Duress Passwords, SSS, Post-Quantum Encryption, Multi-Carrier
"""

from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import io
import json
import secrets
import zlib
from typing import List, Tuple, Optional, Dict, Any
import wave
import struct


# ==================== SHAMIR'S SECRET SHARING ====================

class ShamirSecretSharing:
    """Implementation of Shamir's Secret Sharing Scheme"""
    
    PRIME = 2**127 - 1  # Mersenne prime
    
    @staticmethod
    def _eval_at(poly: List[int], x: int, prime: int) -> int:
        """Evaluate polynomial at x"""
        result = 0
        for coeff in reversed(poly):
            result = (result * x + coeff) % prime
        return result
    
    @staticmethod
    def split_secret(secret: bytes, k: int, n: int) -> List[Tuple[int, int]]:
        """
        Split secret into n shares, requiring k to reconstruct
        Returns list of (x, y) tuples
        """
        if k > n:
            raise ValueError("Threshold k cannot be greater than total shares n")
        if k < 2:
            raise ValueError("Threshold k must be at least 2")
        
        # Convert secret to integer
        secret_int = int.from_bytes(secret, 'big')
        
        # Generate random polynomial with secret as constant term
        polynomial = [secret_int]
        for _ in range(k - 1):
            polynomial.append(secrets.randbelow(ShamirSecretSharing.PRIME))
        
        # Generate shares
        shares = []
        for i in range(1, n + 1):
            x = i
            y = ShamirSecretSharing._eval_at(polynomial, x, ShamirSecretSharing.PRIME)
            shares.append((x, y))
        
        return shares
    
    @staticmethod
    def _lagrange_interpolate(x: int, x_coords: List[int], y_coords: List[int], prime: int) -> int:
        """Lagrange interpolation at x"""
        k = len(x_coords)
        result = 0
        
        for i in range(k):
            xi, yi = x_coords[i], y_coords[i]
            numerator = 1
            denominator = 1
            
            for j in range(k):
                if i != j:
                    xj = x_coords[j]
                    numerator = (numerator * (x - xj)) % prime
                    denominator = (denominator * (xi - xj)) % prime
            
            # Modular inverse
            inv = pow(denominator, prime - 2, prime)
            term = (yi * numerator * inv) % prime
            result = (result + term) % prime
        
        return result
    
    @staticmethod
    def reconstruct_secret(shares: List[Tuple[int, int]], secret_length: int) -> bytes:
        """Reconstruct secret from k shares"""
        if len(shares) < 2:
            raise ValueError("Need at least 2 shares to reconstruct")
        
        x_coords = [share[0] for share in shares]
        y_coords = [share[1] for share in shares]
        
        # Reconstruct secret (polynomial at x=0)
        secret_int = ShamirSecretSharing._lagrange_interpolate(
            0, x_coords, y_coords, ShamirSecretSharing.PRIME
        )
        
        # Convert back to bytes
        byte_length = (secret_int.bit_length() + 7) // 8
        return secret_int.to_bytes(max(byte_length, secret_length), 'big')


# ==================== POST-QUANTUM CRYPTO ====================

class PostQuantumCrypto:
    """Simplified post-quantum key encapsulation mechanism"""
    
    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """Generate PQ public/private keypair (simplified)"""
        # In production, use actual Kyber/Dilithium
        private_key = secrets.token_bytes(32)
        public_key = hashlib.sha256(private_key).digest()
        return public_key, private_key
    
    @staticmethod
    def encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret
        Returns: (ciphertext, shared_secret)
        """
        ephemeral = secrets.token_bytes(32)
        shared_secret = hashlib.sha256(public_key + ephemeral).digest()
        ciphertext = hashlib.sha256(ephemeral).digest()
        return ciphertext, shared_secret
    
    @staticmethod
    def decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate shared secret from ciphertext"""
        public_key = hashlib.sha256(private_key).digest()
        ephemeral = ciphertext
        shared_secret = hashlib.sha256(public_key + ephemeral).digest()
        return shared_secret


# ==================== ADVANCED STEGO ENGINE ====================

class AdvancedStegoEngine:
    """Advanced steganography with multiple security features"""
    
    @staticmethod
    def derive_key(password: str, salt: bytes = None, use_pq: bool = False) -> Tuple[bytes, bytes]:
        """Derive encryption key from password with optional PQ protection"""
        if salt is None:
            salt = secrets.token_bytes(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        if use_pq:
            _, pq_private = PostQuantumCrypto.generate_keypair()
            pq_key = hashlib.sha256(pq_private + key).digest()
            key = pq_key
        
        return base64.urlsafe_b64encode(key), salt
    
    @staticmethod
    def encrypt_text(text: str, password: str, salt: bytes = None, 
                     compress: bool = True, use_pq: bool = False) -> Dict[str, Any]:
        """Encrypt text with optional compression and PQ"""
        data = text.encode()
        if compress:
            data = zlib.compress(data)
        
        key, salt = AdvancedStegoEngine.derive_key(password, salt, use_pq)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)
        
        return {
            'ciphertext': base64.b64encode(encrypted).decode(),
            'salt': base64.b64encode(salt).decode(),
            'compressed': compress,
            'pq_protected': use_pq
        }
    
    @staticmethod
    def decrypt_text(encrypted_data: Dict[str, Any], password: str) -> str:
        """Decrypt text with metadata"""
        try:
            salt = base64.b64decode(encrypted_data['salt'])
            compressed = encrypted_data.get('compressed', False)
            use_pq = encrypted_data.get('pq_protected', False)
            
            key, _ = AdvancedStegoEngine.derive_key(password, salt, use_pq)
            fernet = Fernet(key)
            encrypted = base64.b64decode(encrypted_data['ciphertext'])
            decrypted = fernet.decrypt(encrypted)
            
            if compressed:
                decrypted = zlib.decompress(decrypted)
            
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def create_deniable_payload(
        real_message: str, 
        real_password: str,
        decoy_messages: List[Tuple[str, str]],
        compress: bool = True,
        use_pq: bool = False
    ) -> Dict[str, Any]:
        """Create multi-layer deniable steganography payload"""
        layers = []
        
        # Encrypt real message
        real_encrypted = AdvancedStegoEngine.encrypt_text(
            real_message, real_password, compress=compress, use_pq=use_pq
        )
        real_encrypted['layer_id'] = 'real'
        layers.append(real_encrypted)
        
        # Encrypt decoy messages
        for idx, (decoy_msg, decoy_pass) in enumerate(decoy_messages):
            decoy_encrypted = AdvancedStegoEngine.encrypt_text(
                decoy_msg, decoy_pass, compress=compress, use_pq=use_pq
            )
            decoy_encrypted['layer_id'] = f'decoy_{idx}'
            layers.append(decoy_encrypted)
        
        return {
            'type': 'deniable',
            'layers': layers,
            'num_layers': len(layers)
        }
    
    @staticmethod
    def extract_deniable_payload(payload: Dict[str, Any], password: str) -> Tuple[str, str]:
        """Extract message from deniable payload"""
        if payload.get('type') != 'deniable':
            raise ValueError("Not a deniable payload")
        
        for layer in payload['layers']:
            try:
                message = AdvancedStegoEngine.decrypt_text(layer, password)
                return message, layer['layer_id']
            except:
                continue
        
        raise ValueError("No valid password matched")
    
    @staticmethod
    def create_duress_payload(
        real_message: str,
        real_password: str,
        duress_message: str,
        duress_password: str,
        destroy_on_duress: bool = False
    ) -> Dict[str, Any]:
        """Create payload with duress password support"""
        real_encrypted = AdvancedStegoEngine.encrypt_text(real_message, real_password)
        duress_encrypted = AdvancedStegoEngine.encrypt_text(duress_message, duress_password)
        
        return {
            'type': 'duress',
            'real_layer': real_encrypted,
            'duress_layer': duress_encrypted,
            'destroy_on_duress': destroy_on_duress,
            'duress_activated': False
        }
    
    @staticmethod
    def extract_duress_payload(payload: Dict[str, Any], password: str) -> Tuple[str, bool]:
        """Extract from duress payload. Returns: (message, is_duress_mode)"""
        if payload.get('type') != 'duress':
            raise ValueError("Not a duress payload")
        
        # Try duress first
        try:
            message = AdvancedStegoEngine.decrypt_text(payload['duress_layer'], password)
            return message, True
        except:
            pass
        
        # Try real password
        try:
            message = AdvancedStegoEngine.decrypt_text(payload['real_layer'], password)
            return message, False
        except:
            raise ValueError("Invalid password")


# ==================== MULTI-CARRIER SUPPORT ====================

class MultiCarrierStego:
    """Support for multiple carrier file formats"""
    
    @staticmethod
    def get_carrier_info(carrier_data: bytes, carrier_type: str) -> Dict[str, Any]:
        """Get capacity and metadata for carrier"""
        if carrier_type == 'image':
            img = Image.open(io.BytesIO(carrier_data))
            capacity = (img.width * img.height * 3) // 8
            return {
                'type': 'image',
                'format': img.format,
                'size': (img.width, img.height),
                'capacity_bytes': capacity
            }
        
        elif carrier_type == 'audio':
            wav = wave.open(io.BytesIO(carrier_data), 'rb')
            frames = wav.getnframes()
            capacity = frames // 8
            wav.close()
            return {
                'type': 'audio',
                'format': 'WAV',
                'frames': frames,
                'capacity_bytes': capacity
            }
        
        else:
            raise ValueError(f"Unsupported carrier type: {carrier_type}")
    
    @staticmethod
    def embed_in_image(image: Image.Image, payload: str) -> Image.Image:
        """Embed payload in image using LSB"""
        img = image.convert('RGB')
        binary_payload = ''.join(format(ord(char), '08b') for char in payload)
        
        delimiter = '1111111111111110'
        length_binary = format(len(binary_payload), '032b')
        full_binary = length_binary + binary_payload + delimiter
        
        pixels = list(img.getdata())
        max_bits = len(pixels) * 3
        
        if len(full_binary) > max_bits:
            raise ValueError("Payload too large for image carrier")
        
        new_pixels = []
        binary_index = 0
        
        for pixel in pixels:
            r, g, b = pixel
            new_pixel = [r, g, b]
            
            for channel_idx in range(3):
                if binary_index < len(full_binary):
                    new_pixel[channel_idx] = (new_pixel[channel_idx] & 0xFE) | int(full_binary[binary_index])
                    binary_index += 1
            
            new_pixels.append(tuple(new_pixel))
        
        stego_img = Image.new(img.mode, img.size)
        stego_img.putdata(new_pixels)
        return stego_img
    
    @staticmethod
    def extract_from_image(image: Image.Image) -> str:
        """Extract payload from image"""
        img = image.convert('RGB')
        pixels = list(img.getdata())
        
        binary_data = ''
        for pixel in pixels:
            for channel in pixel:
                binary_data += str(channel & 1)
        
        msg_length = int(binary_data[:32], 2)
        if msg_length <= 0 or msg_length > len(binary_data) - 32:
            raise ValueError("Invalid payload in image")
        
        payload_binary = binary_data[32:32 + msg_length]
        payload = ''.join(
            chr(int(payload_binary[i:i+8], 2)) 
            for i in range(0, len(payload_binary), 8)
        )
        
        return payload
    
    @staticmethod
    def embed_in_audio(audio_data: bytes, payload: str) -> bytes:
        """Embed payload in WAV audio using LSB"""
        input_wav = wave.open(io.BytesIO(audio_data), 'rb')
        params = input_wav.getparams()
        frames = input_wav.readframes(input_wav.getnframes())
        input_wav.close()
        
        samples = list(struct.unpack(f'{len(frames)//2}h', frames))
        
        binary_payload = ''.join(format(ord(char), '08b') for char in payload)
        length_binary = format(len(binary_payload), '032b')
        full_binary = length_binary + binary_payload
        
        if len(full_binary) > len(samples):
            raise ValueError("Payload too large for audio carrier")
        
        for i, bit in enumerate(full_binary):
            samples[i] = (samples[i] & 0xFFFE) | int(bit)
        
        output = io.BytesIO()
        output_wav = wave.open(output, 'wb')
        output_wav.setparams(params)
        output_wav.writeframes(struct.pack(f'{len(samples)}h', *samples))
        output_wav.close()
        
        return output.getvalue()
    
    @staticmethod
    def extract_from_audio(audio_data: bytes) -> str:
        """Extract payload from WAV audio"""
        wav = wave.open(io.BytesIO(audio_data), 'rb')
        frames = wav.readframes(wav.getnframes())
        wav.close()
        
        samples = list(struct.unpack(f'{len(frames)//2}h', frames))
        binary_data = ''.join(str(sample & 1) for sample in samples)
        
        msg_length = int(binary_data[:32], 2)
        if msg_length <= 0 or msg_length > len(binary_data) - 32:
            raise ValueError("Invalid payload in audio")
        
        payload_binary = binary_data[32:32 + msg_length]
        payload = ''.join(
            chr(int(payload_binary[i:i+8], 2)) 
            for i in range(0, len(payload_binary), 8)
        )
        
        return payload


# ==================== HELPER FUNCTIONS ====================

def image_from_base64(base64_string: str) -> Image.Image:
    """Convert base64 string to PIL Image"""
    if ',' in base64_string:
        base64_string = base64_string.split(',')[1]
    image_bytes = base64.b64decode(base64_string)
    return Image.open(io.BytesIO(image_bytes))


def image_to_base64(image) -> str:

    buffered = io.BytesIO()
    image.save(buffered, format="PNG")
    b64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{b64}"  # must have this prefix


def bytes_to_base64(data: bytes, mime_type: str = "application/octet-stream") -> str:
    """Convert bytes to base64 data URI"""
    b64 = base64.b64encode(data).decode()
    return f"data:{mime_type};base64,{b64}"


def base64_to_bytes(base64_string: str) -> bytes:
    """Convert base64 data URI to bytes"""
    if ',' in base64_string:
        base64_string = base64_string.split(',')[1]
    return base64.b64decode(base64_string)


# ==================== MAIN API FUNCTIONS ====================

def hide_message_advanced(
    image: Image.Image,
    message: str,
    password: str,
    options: Dict[str, Any] = None
) -> Image.Image:
    """
    Hide message with advanced features
    Options:
        - mode: 'standard', 'deniable', 'duress'
        - compress: bool
        - use_pq: bool
        - decoy_messages: List[(msg, pass)]
        - duress_message: str
        - duress_password: str
    """
    if options is None:
        options = {}
    
    mode = options.get('mode', 'standard')
    compress = options.get('compress', True)
    use_pq = options.get('use_pq', False)
    
    if mode == 'deniable':
        decoy_messages = options.get('decoy_messages', [])
        payload_data = AdvancedStegoEngine.create_deniable_payload(
            message, password, decoy_messages, compress, use_pq
        )
    elif mode == 'duress':
        duress_message = options.get('duress_message', 'Nothing to see here')
        duress_password = options.get('duress_password', 'panic123')
        destroy = options.get('destroy_on_duress', False)
        payload_data = AdvancedStegoEngine.create_duress_payload(
            message, password, duress_message, duress_password, destroy
        )
    else:
        # Standard mode
        payload_data = AdvancedStegoEngine.encrypt_text(message, password, compress=compress, use_pq=use_pq)
    
    # Serialize payload
    payload_json = json.dumps(payload_data)
    
    # Embed in image
    return MultiCarrierStego.embed_in_image(image, payload_json)


def extract_message_advanced(
    image: Image.Image,
    password: str
) -> Dict[str, Any]:
    """
    Extract message with advanced features
    Returns dict with message and metadata
    """
    # Extract payload
    payload_json = MultiCarrierStego.extract_from_image(image)
    payload_data = json.loads(payload_json)
    
    mode = payload_data.get('type', 'standard')
    
    if mode == 'deniable':
        message, layer_id = AdvancedStegoEngine.extract_deniable_payload(payload_data, password)
        is_decoy = 'decoy' in layer_id
        return {
            'message': message,
            'mode': 'deniable',
            'is_decoy': is_decoy,
            'layer': layer_id
        }
    elif mode == 'duress':
        message, is_duress = AdvancedStegoEngine.extract_duress_payload(payload_data, password)
        return {
            'message': message,
            'mode': 'duress',
            'is_duress': is_duress
        }
    else:
        message = AdvancedStegoEngine.decrypt_text(payload_data, password)
        return {
            'message': message,
            'mode': 'standard'
        }
