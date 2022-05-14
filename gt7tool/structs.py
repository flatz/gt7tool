from .constants import INDEX_MAGIC, FORMATTER_CODE, MAX_VOLUMES, \
                       CLUSTER_MAGIC, PACKED_FILE_ZSTD_TINY_MAGIC, PACKED_FILE_ZSTD_REGULAR_MAGIC, PACKED_FILE_ZSTD_CHUNK_MAGIC, PACKED_FILE_ZLIB_MAGIC, \
                       DATA_ALIGNMENT, CHUNK_ALIGNMENT, \
                       FORMAT_PLAIN, FORMAT_PZ1, FORMAT_PZ2, FORMAT_PFS, \
                       KIND_LUMP, KIND_FRAG, \
                       ALGO_ZLIB, ALGO_ZSTD, ALGO_KRAKEN, \
                       NODE_FLAG_FORMAT_MASK, NODE_FLAG_FORMAT_SHIFT, NODE_FLAG_KIND_MASK, NODE_FLAG_KIND_SHIFT, NODE_FLAG_ALGO_MASK, NODE_FLAG_ALGO_SHIFT, \
                       NODE_EXTRA_FLAG_UNK_MASK, NODE_EXTRA_FLAG_UNK_SHIFT, \
                       NODE_EXTRA_FLAG_USE_VOLUME_MASK, NODE_EXTRA_FLAG_USE_VOLUME_SHIFT, \
                       CACHE_NAME_LOOKUP_TABLE

from typing import Optional

from zlib import compress as zlib_compress, decompress as zlib_decompress
from pyzstd import compress as zstd_compress, decompress as zstd_decompress

from construct import Struct, Const, Tell, Hex, Computed, RestreamData, Tunnel, GreedyBytes, GreedyRange, If, Switch, Check, \
                      Bytes, PaddedString, Padding, \
                      Int8ub, Int16ul, Int32ul, Int32sl, Int64ul, BytesInteger, \
                      this, len_

def stringify_algo(algo: int) -> Optional[str]:
	return {
		ALGO_ZLIB: 'ZLIB',
		ALGO_ZSTD: 'ZSTD',
		ALGO_KRAKEN: 'KRKN',
	}.get(algo, None)

def stringify_format(format: int) -> Optional[str]:
	return {
		FORMAT_PLAIN: 'PLAIN',
		FORMAT_PZ1: 'PZ1',
		FORMAT_PZ2: 'PZ2',
		FORMAT_PFS: 'PFS',
	}.get(format, None)

def stringify_kind(kind: int) -> Optional[str]:
	return {
		KIND_LUMP: 'LUMP',
		KIND_FRAG: 'FRAG',
	}.get(kind, '????')

def compute_cache_key(x):
	def g(x, i):
		return CACHE_NAME_LOOKUP_TABLE[(x // (36 ** i)) % 36]

	result = ''
	for i in range(2):
		result += g(x, i) + '/'
	result += CACHE_NAME_LOOKUP_TABLE[1 if x >= 0x81BF0FFF else 0]
	for i in range(5, 1, -1):
		result += g(x, i)

	return result

class RawHexDisplayedBytes(bytes):
	def __repr__(self):
		if not hasattr(self, 'render'):
			self.render = self.hex().upper()
		return self.render

class RawHex(Hex):
	def _decode(self, obj, context, path):
		if isinstance(obj, bytes):
			return RawHexDisplayedBytes(obj)
		return super()._decode(obj, context, path)

class CompressedZlib(Tunnel):
	def __init__(self, subcon):
		super().__init__(subcon)

	def _decode(self, obj, context, path):
		return zlib_decompress(obj)

	def _encode(self, obj, context, path):
		# TODO: Figure out parameters.
		return zlib_compress(obj)

class CompressedZStd(Tunnel):
	def __init__(self, subcon):
		super().__init__(subcon)

	def _decode(self, obj, context, path):
		return zstd_decompress(obj)

	def _encode(self, obj, context, path):
		# TODO: Figure out parameters.
		return zstd_compress(obj)

VolumeInfo = Struct(
	'file_name' / PaddedString(0x10, 'ascii'), # 0x00
	'chunk_index' / Int8ub,                    # 0x10
	'unk_0x11' / Hex(Int16ul),                 # 0x11
	'_volume_size_hi' / Hex(Int8ub),           # 0x13
	'_volume_size_lo' / Hex(Int32ul),          # 0x14

	'volume_size' / Hex(Computed(
		# Volume size is encoded as 40-bit number.
		(this._volume_size_hi << 32) | this._volume_size_lo
	)),
)

SuperintendentHeader = Struct(
	'magic' / RawHex(Const(INDEX_MAGIC, Int32ul)),          # 0x00
	'unk_0x04' / Hex(Int32ul),                              # 0x04
	'timestamp' / Hex(Int64ul),                             # 0x08
	'serial_number' / Hex(Int64ul),                         # 0x10
	'unk_0x18' / Hex(Int32ul),                              # 0x18
	'flags' / Hex(Int32ul),                                 # 0x1C
	'formatter_code' / Hex(Const(FORMATTER_CODE, Int32ul)), # 0x20
	'index_data_offset' / Hex(Int32ul),                     # 0x24
	'index_data_size' / Hex(Int32ul),                       # 0x28
	'node_table_offset' / Hex(Int32ul),                     # 0x2C
	'node_table_size' / Hex(Int32ul),                       # 0x30
	'volume_info_count' / Int32ul,                          # 0x34
	'volume_infos' / VolumeInfo[this.volume_info_count],    # 0x38

	Check(this.volume_info_count < MAX_VOLUMES),
)

SuperintendentHeaderV2 = Struct(
	'magic' / RawHex(Const(INDEX_MAGIC, Int32ul)),          # 0x00
	'unk_0x04' / Hex(Int32ul),                              # 0x04
	'timestamp' / Hex(Int64ul),                             # 0x08
	'serial_number' / Hex(Int64ul),                         # 0x10
	'unk_0x18' / Hex(Int32ul),                              # 0x18
	'flags' / Hex(Int32ul),                                 # 0x1C
	'formatter_code' / Hex(Const(FORMATTER_CODE, Int32ul)), # 0x20
	'index_data_offset' / Hex(Int32ul),                     # 0x24
	'index_data_size' / Hex(Int32ul),                       # 0x28
	'node_table_offset' / Hex(Int32ul),                     # 0x2C
	'node_table_size' / Hex(Int32ul),                       # 0x30
	'volume_info_offset' / Hex(Int32ul),                    # 0x34
	'volume_info_count' / Hex(Int32ul),                     # 0x38
	'header_size' / Hex(Int64ul),                           # 0x3C
	'digest' / RawHex(Bytes(0x10)),                         # 0x44
	'volume_infos' / VolumeInfo[this.volume_info_count],    # 0x58

	Check(this.volume_info_count < MAX_VOLUMES),
)

ClusterVolumeHeader = Struct(
	'magic' / RawHex(Const(CLUSTER_MAGIC, Int64ul)), # 0x00
	'sector_size' / Hex(Int32ul),                    # 0x08
	'cluster_size' / Hex(Int32ul),                   # 0x0C
	'volume_size' / Hex(Int64ul),                    # 0x10
	'flags' / Hex(Int32ul),                          # 0x18
	'seed' / Hex(Int32ul),                           # 0x1C

	Check(
		# Sector size should be aligned.
		(this.sector_size + DATA_ALIGNMENT - 1) & ~(DATA_ALIGNMENT - 1) == this.sector_size
	),

	Check(
		# Cluster size should be aligned.
		(this.cluster_size + DATA_ALIGNMENT - 1) & ~(DATA_ALIGNMENT - 1) == this.cluster_size
	),
)

IndexData = Struct(
	'node_count' / Int32ul,
	'exists_count' / Int64ul,
	'_exists' / Hex(Int32sl)[this.exists_count],
	'exists_acm256_count' / Int64ul,
	'_exists_acm256' / Hex(Int32sl)[this.exists_acm256_count],
	'exists_acm32_count' / Int64ul,
	'_exists_acm32' / Hex(Int8ub)[this.exists_acm32_count],
	'vertex_count' / Int32ul,
	'seeds' / Hex(Int32ul)[3],
	'g_value_count' / Int64ul,
	'_g_values' / Hex(Int8ub)[this.g_value_count],
)

NodeInfo = Struct(
	'entry_hash' / Hex(Int32ul),            # 0x00: FNV-1a
	'_compressed_size_lo' / Hex(Int32ul),   # 0x04
	'nonce' / Hex(Int32ul),                 # 0x08
	'_uncompressed_size_lo' / Hex(Int32ul), # 0x0C
	'encoded_data' / Hex(Int32ul),          # 0x10
	'_compressed_size_hi' / Hex(Int8ub),    # 0x14
	'flags' / Hex(Int8ub),                  # 0x15
	'_uncompressed_size_hi' / Hex(Int8ub),  # 0x16
	'extra_flags' / Hex(Int8ub),            # 0x17

	'format' / Computed(
		(this.flags & NODE_FLAG_FORMAT_MASK) >> NODE_FLAG_FORMAT_SHIFT
	),
	'kind' / Computed(
		(this.flags & NODE_FLAG_KIND_MASK) >> NODE_FLAG_KIND_SHIFT
	),
	'algo' / Computed(
		(this.flags & NODE_FLAG_ALGO_MASK) >> NODE_FLAG_ALGO_SHIFT
	),

	'attrs' / Computed(lambda ctx:
		'-'.join([
			stringify_algo(ctx.algo), stringify_format(ctx.format), stringify_kind(ctx.kind)
		]) if ctx.format != FORMAT_PLAIN else stringify_format(ctx.format)
	),

	'is_encrypted' / Computed(
		this.format != FORMAT_PLAIN
	),

	'is_compressed' / Computed(
		this.format != FORMAT_PLAIN
	),

	'is_fragmented' / Computed(
		this.format != FORMAT_PLAIN and this.kind == KIND_FRAG
	),

	'use_volume' / Computed(
		((this.extra_flags & NODE_EXTRA_FLAG_USE_VOLUME_MASK) >> NODE_EXTRA_FLAG_USE_VOLUME_SHIFT) != 0
	),

	'volume_index' / Computed(
		# Volume index is encoded as 7-bit number.
		(this.encoded_data >> 25) & 0x7F,
	),

	'sector_index' / Computed(
		# Sector index is encoded as 25-bit number.
		this.encoded_data & 0x1FFFFFF,
	),

	'compressed_size' / Hex(Computed(
		# Compressed size is encoded as 40-bit number.
		(this._compressed_size_hi << 32) | this._compressed_size_lo,
	)),

	'uncompressed_size' / Hex(Computed(
		# Uncompressed size is encoded as 40-bit number.
		(this._uncompressed_size_hi << 32) | this._uncompressed_size_lo,
	)),

	'cache_key' / Computed(lambda ctx:
		compute_cache_key(ctx.encoded_data)
	),
)

NodeTable = Struct(
	'count' / Computed(this._params.count),
	'nodes' / NodeInfo[this.count],
)

PackedFileZStdTiny = Struct(
	'_uncompressed_size' / Int32sl,  # 0x04

	# Uncompressed size is stored as negative number.
	'uncompressed_size' / Computed(-this._uncompressed_size),

	'compressed_data' / GreedyBytes, # 0x08

	'compressed_size' / Computed(lambda ctx: len(ctx.compressed_data)),

	'uncompressed_data' / RestreamData(
		this.compressed_data,
		CompressedZStd(Bytes(this.uncompressed_size))
	),

	Check(len_(this.uncompressed_data) == this.uncompressed_size),
)

PackedFileZStdChunk = Struct(
	'_start_offset' / Hex(Tell),

	If(this._index > 0,
		Padding(CHUNK_ALIGNMENT - this._start_offset % CHUNK_ALIGNMENT)
	),

	'magic' / RawHex(Const(PACKED_FILE_ZSTD_CHUNK_MAGIC, Int32ul)), # 0x00
	'uncompressed_size' / Hex(Int32ul),                             # 0x04
	'compressed_size' / Hex(Int32ul),                               # 0x08
	'checksum' / Hex(Int32ul),                                      # 0x0C
	'compressed_data' / Bytes(this.compressed_size),                # 0x10
	'end_offset' / Hex(Tell),

	'uncompressed_data' / RestreamData(
		this.compressed_data,
		CompressedZStd(Bytes(this.uncompressed_size))
	),

	Check(len_(this.compressed_data) == this.compressed_size),
	Check(len_(this.uncompressed_data) == this.uncompressed_size),
)

PackedFileZStdRegular = Struct(
	'uncompressed_size' / Hex(BytesInteger(0x6, swapped = True)), # 0x04
	'compressed_size' / Hex(BytesInteger(0x6, swapped = True)),   # 0x0A
	Padding(0xC),                                                 # 0x10
	'unk_0x1C' / Hex(Int8ub),                                     # 0x1C
	'unk_0x1D' / Hex(Int8ub),                                     # 0x1D
	'unk_0x1E' / Hex(Int8ub),                                     # 0x1E
	'unk_0x1F' / Hex(Int8ub),                                     # 0x1F

	'entire' / If(lambda ctx: not ctx._params.is_fragmented, Struct(
		'compressed_data' / Bytes(this._.compressed_size),        # 0x20

		'uncompressed_data' / RestreamData(
			this.compressed_data,
			CompressedZStd(Bytes(this._.uncompressed_size))
		),

		Check(len_(this.compressed_data) == this._.compressed_size),
		Check(len_(this.uncompressed_data) == this._.uncompressed_size),
	)),

	'chunks' / If(lambda ctx: ctx._params.is_fragmented,
		GreedyRange(PackedFileZStdChunk)                         # 0x20
	),
)

PackedFileZlib = Struct(
	'_compressed_size' / Int32sl,                    # 0x04

	# Compressed size is stored as negative number.
	'compressed_size' / Computed(-this._compressed_size),

	'compressed_data' / Bytes(this.compressed_size), # 0x08

	'uncompressed_data' / RestreamData(
		this.compressed_data,
		CompressedZlib(GreedyBytes)
	),

	'uncompressed_size' / Computed(lambda ctx: len(ctx.uncompressed_data)),

	Check(len_(this.compressed_data) == this.compressed_size),
)

PackedFile = Struct(
	'magic' / Hex(Int32ul), # 0x00

	'inner' / Switch(this.magic, {
		PACKED_FILE_ZSTD_TINY_MAGIC: PackedFileZStdTiny,
		PACKED_FILE_ZSTD_REGULAR_MAGIC: PackedFileZStdRegular,
		PACKED_FILE_ZLIB_MAGIC: PackedFileZlib,
	}),
)
