#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .constants import VOLUME_CIPHER_KEY

from .index import IndexFile

from .crypto import chacha20_decrypt, \
                    get_stream_cryptor_iv

from .structs import PackedFile

from .util import CmdLineParser, \
                  ColoredFormatter, ShutdownHandler, \
                  write_binary

from typing import Optional

from logging import StreamHandler, getLogger, debug, info, warning, fatal, DEBUG, INFO

from construct import setGlobalPrintFullStrings

from os import getcwd, makedirs
from os.path import split as split_path, join as join_path, isdir

def _unpack_node(index_file: IndexFile, node: object, index: int, output_dir: str) -> None:
	assert node.use_volume

	volume_file_path, volume_info = index_file.get_volume(node.volume_index)
	info(f'Reading volume file: {volume_file_path}')

	# TODO: Add support for encryption flag if it exists.

	with open(volume_file_path, 'rb') as f:
		f.seek(node.sector_index * volume_info.sector_size)
		data = f.read(node.compressed_size)
		volume_cipher_iv = get_stream_cryptor_iv(node.nonce)
		data = chacha20_decrypt(VOLUME_CIPHER_KEY, volume_cipher_iv, data)

	if node.is_compressed:
		packed_file_fields = PackedFile.parse(data)
		fields = packed_file_fields.inner
		while True:
			if hasattr(fields, 'sub'):
				fields = fields.sub
				continue
			if hasattr(fields, 'inner'):
				fields = fields.inner
				continue
			break
		data = fields.uncompressed_data

	out_file_path = join_path(output_dir, f'0x{node.entry_hash:08X}.bin')
	out_file_dir = split_path(out_file_path)[0]
	if not isdir(out_file_dir):
		makedirs(out_file_dir)

	info(f'Writing to: {out_file_path}')
	write_binary(out_file_path, data)

def _dump_node(index_file: IndexFile, node: object, index: int) -> None:
	info(f'Entry hash: 0x{node.entry_hash:08X}')
	info(f'Format: 0x{node.format:X}')
	info(f'Kind: 0x{node.kind:X}')
	info(f'Algo: 0x{node.algo:X}')
	info(f'Nonce: 0x{node.nonce:08X}')
	info(f'Flags: 0x{node.flags:X}')
	info(f'Extra flags: 0x{node.extra_flags:X}')
	info(f'Attributes: {node.attrs}')
	info(f'Use volume: {node.use_volume}')
	if node.use_volume:
		volume_file_path, volume_info = index_file.get_volume(node.volume_index)
		offset = node.sector_index * volume_info.sector_size
		info(f'Volume index: {node.volume_index}')
		info(f'Volume file path: {volume_file_path}')
		info(f'Sector index: {node.sector_index}')
		info(f'Offset: 0x{offset:X}')
	if node.is_compressed:
		info(f'Compressed size: 0x{node.compressed_size:X}')
		info(f'Uncompressed size: 0x{node.uncompressed_size:X}')
	else:
		info(f'Size: 0x{node.compressed_size:X}')
	info(f'Cache key: {node.cache_key}')

def main():
	work_dir = getcwd()

	parser = CmdLineParser('Gran Turismo 7 unpacker')

	subparser = parser.add_subparser('list', 'list file entries')
	subparser.add_argument('index_path', type = str, help = 'path to gt.idx file', metavar = 'index-path')

	subparser = parser.add_subparser('info', 'get information about files')
	subparser.add_argument('-e', '--use-entry-hash', action = 'store_true', help = 'use entry hashes instead of file paths')
	subparser.add_argument('-c', '--use-cache-key', action = 'store_true', help = 'use cache key instead of file paths')
	subparser.add_argument('index_path', type = str, help = 'path to gt.idx file', metavar = 'index-path')
	subparser.add_argument('files', type = str, nargs = '+', help = 'file path', metavar = 'path')

	subparser = parser.add_subparser('unpack', 'unpack files from volumes')
	subparser.add_argument('-o', '--output-dir', type = str, default = work_dir, help = 'output directory', metavar = 'dir')
	subparser.add_argument('-e', '--use-entry-hash', action = 'store_true', help = 'use entry hashes instead of file paths')
	subparser.add_argument('-c', '--use-cache-key', action = 'store_true', help = 'use cache key instead of file paths')
	subparser.add_argument('index_path', type = str, help = 'path to gt.idx file', metavar = 'index-path')
	subparser.add_argument('files', type = str, nargs = '+', help = 'file path', metavar = 'path')

	subparser = parser.add_subparser('unpack-all', 'unpack all files from volumes')
	subparser.add_argument('-o', '--output-dir', type = str, default = work_dir, help = 'output directory', metavar = 'dir')
	subparser.add_argument('index_path', type = str, help = 'path to gt.idx file', metavar = 'index-path')

	subparser = parser.add_subparser('cache-key', 'generate cache key')
	subparser.add_argument('index_path', type = str, help = 'path to gt.idx file', metavar = 'index-path')
	subparser.add_argument('files', type = str, nargs = '+', help = 'file path', metavar = 'path')

	#subparser = parser.add_subparser('disas', 'disassemble compiled adhoc script')
	#subparser.add_argument('-o', '--output-file', type = str, help = 'output file', metavar = 'path')
	#subparser.add_argument('in_path', type = str, help = '.adc file path', metavar = 'path')

	args = parser.parse_args()

	channel = StreamHandler()
	channel.setFormatter(ColoredFormatter())

	logger = getLogger()
	logger.addHandler(channel)
	logger.addHandler(ShutdownHandler())

	if args.debug:
		logger.setLevel(DEBUG)

		setGlobalPrintFullStrings(True)
	else:
		logger.setLevel(INFO)

	delimiter = '-' * 64

	if args.action in ['info', 'unpack', 'cache-key']:
		index_file = IndexFile(args.index_path, args.debug)

		need_cache_key = args.action == 'cache-key'

		for in_file_path in args.files:
			if not need_cache_key and args.use_entry_hash:
				entry_hash = int(in_file_path, 0)
				node, node_index = index_file.get_node_by_entry_hash(entry_hash)
			elif not need_cache_key and args.use_cache_key:
				node, node_index = index_file.get_node_by_cache_key(in_file_path)
			else:
				node, node_index = index_file.get_node_by_path(in_file_path)
				if node is not None:
					info(f'Node 0x{node.entry_hash:08X} found for file: {in_file_path}')

			if node is None:
				warning(f'Entry not found: {in_file_path}')
				continue

			if args.action == 'unpack':
				_unpack_node(index_file, node, node_index, args.output_dir)
			elif args.action == 'info':
				_dump_node(index_file, node, node_index)
			elif args.action == 'cache-key':
				info(f'Cache key: {node.cache_key}')
	elif args.action == 'list':
		def dump_node(index_file: IndexFile, node: object, index: int) -> None:
			_dump_node(index_file, node, index)
			info(delimiter)

		index_file = IndexFile(args.index_path, args.debug)
		index_file.traverse_nodes(dump_node)
	elif args.action == 'unpack-all':
		def unpack_node(index_file: IndexFile, node: object, index: int, output_dir: str) -> None:
			if node.attrs == 'PLAIN':
				return
			info(f'Unpacking file: 0x{node.entry_hash:08X}')
			_unpack_node(index_file, node, index, output_dir)
			info(delimiter)

		index_file = IndexFile(args.index_path, args.debug)
		index_file.traverse_nodes(unpack_node, args.output_dir)

if __name__ == '__main__':
	main()
