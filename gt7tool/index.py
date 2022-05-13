from .constants import INDEX_HEADER_SIZE, \
                       INDEX_CIPHER_KEY, INDEX_CIPHER_IV

from .crypto import chacha20_decrypt, crc32_decrypt, \
                    fnv1a

from .structs import SuperintendentHeader, SuperintendentHeaderV2, \
                     VolumeInfo, \
                     IndexData, \
                     NodeTable, NodeInfo, \
                     ClusterVolumeHeader

from .util import uint32, uint64, \
                  popcnt64, \
                  read_binary

from typing import Optional, Tuple

from logging import debug

from os.path import split as split_path, join as join_path

# GT7's Minimal Perfect Hash implementation is based on: https://github.com/iwiwi/minimal-perfect-hash

def mph_get_hash_single(key: int, seed: int, limit: int) -> int:
	return uint32(
		uint64(key * 1350490027 + 123456789012345) % seed % limit
	) 

def mph_get_hash_from_string(key: str, seed: int, limit: int) -> int:
	s = uint32(seed)
	h = 1111111111

	for c in map(ord, key):
		s = uint32(s * 1504569917 + 987987987)
		h = uint32(
			(uint64(h * 103) % seed) + mph_get_hash_single(c, s, limit)
		)

	return uint32(h % seed % limit)

class IndexFile:
	def __init__(self, index_file_path: str, is_new_format: bool = False, is_debug: bool = False) -> None:
		self.__is_new_format = is_new_format
		self.__is_debug = is_debug

		index_dir = split_path(index_file_path)[0]
		entire_data = read_binary(index_file_path)

		entire_data = chacha20_decrypt(INDEX_CIPHER_KEY, INDEX_CIPHER_IV, entire_data)
		header_data = crc32_decrypt(entire_data[:INDEX_HEADER_SIZE])

		header_class = SuperintendentHeader if not self.__is_new_format else SuperintendentHeaderV2
		header_fields = header_class.parse(header_data)

		if self.__is_debug:
			debug('Superintendent header:')
			debug(header_fields)

		volumes = []

		for i in range(header_fields.volume_info_count):
			volume_info = header_fields.volume_infos[i]

			volume_file_path = join_path(index_dir, volume_info.file_name)
			data = read_binary(volume_file_path, ClusterVolumeHeader.sizeof())
			volume_fields = ClusterVolumeHeader.parse(data)

			if self.__is_debug:
				debug(f'Volume[{i:02}] header:')
				debug(volume_fields)

			volumes.append((volume_file_path, volume_fields))

		index_data = entire_data[header_fields.index_data_offset:header_fields.index_data_offset + header_fields.index_data_size]
		index_fields = IndexData.parse(index_data)

		if self.__is_debug:
			debug('Index data:')
			debug(index_fields)

		node_info_table_data = entire_data[header_fields.node_table_offset:header_fields.node_table_offset + header_fields.node_table_size]
		assert index_fields.node_count * NodeInfo.sizeof() == len(node_info_table_data)

		self.__header_fields = header_fields
		self.__index_fields = index_fields
		self.__volumes = volumes
		self.__node_info_table_data = node_info_table_data
		self.__node_info_table_fields = None
		self.__node_entry_hash_map = None
		self.__node_cache_key_map = None

		if self.__is_debug:
			self._populate_node_info_maps()

	def traverse_nodes(self, cb, *args, **kwargs) -> int:
		self._populate_node_info_maps()

		count = 0

		if not callable(cb):
			cb = None

		for i, node in enumerate(self.__node_info_table_fields.nodes):
			if cb:
				result = cb(self, node, i, *args, **kwargs)
				if isinstance(result, bool) and not result:
					break
			count += 1

		return count

	def get_volume_count(self) -> int:
		return len(self.__volumes)

	def get_volume(self, index: int) -> Tuple[str, object]:
		assert index >= 0 and index < self.get_volume_count()
		return self.__volumes[index]

	def get_volume_path(self, index: int) -> str:
		return self.get_volume(index)[0]

	def get_volume_info(self, index: int) -> VolumeInfo:
		return self.get_volume(index)[1]

	def get_node_count(self) -> int:
		return self.__index_fields.node_count

	def get_node_index(self, path: str) -> int:
		limit = self.__index_fields.vertex_count

		indices = [
			mph_get_hash_from_string(path, self.__index_fields.seeds[0], limit),
			mph_get_hash_from_string(path, self.__index_fields.seeds[1], limit) + limit,
			mph_get_hash_from_string(path, self.__index_fields.seeds[2], limit) + limit * 2,
		]
		index = (self.__get_g(indices[0]) + self.__get_g(indices[1]) + self.__get_g(indices[2])) % 3
		index = indices[index]

		node_index = self.__index_fields._exists_acm256[index // 256]
		node_index += self.__index_fields._exists_acm32[index // 32]
		node_index += popcnt64(
			self.__index_fields._exists[index // 32] & ((1 << (index % 32)) - 1)
		)

		if self.__is_debug:
			debug(f'Node index: {node_index}')

		assert node_index >= 0 and node_index < self.get_node_count()

		return node_index

	def get_node_by_index(self, index: int) -> Optional[object]:
		if index >= 0 and index < self.get_node_count():
			node_info_size = NodeInfo.sizeof()
			node_info_data = self.__node_info_table_data[index * node_info_size:(index + 1) * node_info_size]
			node_info_fields = NodeInfo.parse(node_info_data)

			if self.__is_debug:
				debug(f'Node[{index}]:')
				debug(node_info_fields)

			return node_info_fields
		else:
			return None

	def get_node_by_path(self, path: str) -> Optional[object]:
		node_index = self.get_node_index(path)

		node_info_fields = self.get_node_by_index(node_index)
		if node_info_fields is None:
			return None, None

		real_entry_hash = fnv1a(path)
		if node_info_fields.entry_hash != real_entry_hash:
			return None, None

		return node_info_fields, node_index

	def get_node_by_entry_hash(self, entry_hash: int) -> Optional[object]:
		self._populate_node_info_maps()

		if entry_hash not in self.__node_entry_hash_map:
			return None, None

		node_index, node_info_fields = self.__node_entry_hash_map[entry_hash]

		if self.__is_debug:
			debug(f'Node[{node_index}]:')
			debug(node_info_fields)

		return node_info_fields, node_index

	def get_node_by_cache_key(self, cache_key: str) -> Optional[object]:
		self._populate_node_info_maps()

		if cache_key not in self.__node_cache_key_map:
			return None, None

		node_index, node_info_fields = self.__node_cache_key_map[cache_key]

		if self.__is_debug:
			debug(f'Node[{node_index}]:')
			debug(node_info_fields)

		return node_info_fields, node_index

	def _populate_node_info_maps(self) -> None:
		if self.__node_info_table_fields is not None:
			return

		node_count = self.get_node_count()

		self.__node_info_table_fields = NodeTable.parse(self.__node_info_table_data, count = node_count)

		debug('Node info table:')
		debug(self.__node_info_table_fields)

		self.__node_entry_hash_map = {}
		self.__node_cache_key_map = {}

		for i in range(node_count):
			node_info_fields = self.__node_info_table_fields.nodes[i]

			self.__node_entry_hash_map[node_info_fields.entry_hash] = (i, node_info_fields)
			self.__node_cache_key_map[node_info_fields.cache_key] = (i, node_info_fields)

	def __get_g(self, index: int) -> int:
		return (self.__index_fields._g_values[index // 4] >> ((index % 4) * 2)) & 0x3
