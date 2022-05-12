from .constants import CRC32_TABLE, \
                       CIPHER_INITIAL_CRC

from .util import uint32

from Crypto.Cipher import ChaCha20

def chacha20_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
	cipher = ChaCha20.new(key = key, nonce = iv)
	return cipher.decrypt(data)

def crc32_decrypt(data: bytes, crc: int = CIPHER_INITIAL_CRC) -> bytes:
	stride = 4
	result = bytearray()

	for i in range(len(data) // stride):
		value = int.from_bytes(data[i * stride:(i + 1) * stride], byteorder = 'little')

		a = (crc >> 24) & 0xFF
		b = (crc >> 16) & 0xFF
		c = (crc >> 8) & 0xFF
		d = (crc >> 0) & 0xFF

		crc = value

		value = CRC32_TABLE[a]
		value = uint32(value << 8) ^ CRC32_TABLE[b ^ (value >> 24)]
		value = uint32(value << 8) ^ CRC32_TABLE[c ^ (value >> 24)]
		value = uint32(value << 8) ^ CRC32_TABLE[d ^ (value >> 24)]
		value = ~(value ^ crc)

		result += int.to_bytes(uint32(value), length = stride, byteorder = 'little')

	return bytes(result)

def get_stream_cryptor_iv(nonce):
	# XXX: Nonce should be padded from the right with zeros.
	return int.to_bytes(uint32(nonce), length = 0x8 + 0x4, byteorder = 'little')

def fnv1a(s: str) -> int:
	result, prime = 2166136261, 16777619

	for c in s:
		result ^= ord(c)
		result = uint32(result * prime)

	return result
