from typing import Optional, Tuple, List

from logging import LogRecord, Formatter, StreamHandler, DEBUG, INFO, WARNING, ERROR, CRITICAL
from argparse import ArgumentParser, Namespace, Action, HelpFormatter, RawDescriptionHelpFormatter, SUPPRESS

from sys import argv, stderr, exit

from signal import SIGINT

from traceback import format_exc

def round_up(x: int, alignment: int) -> int:
	return (x + (alignment - 1)) & ~(alignment - 1)

def trunc_down(x: int, alignment: int) -> int:
	return x & ~(alignment - 1)

def uint8(x: int) -> int:
	return x & 0xFF

def uint16(x: int) -> int:
	return x & 0xFFFF

def uint32(x: int) -> int:
	return x & 0xFFFFFFFF

def uint64(x: int) -> int:
	return x & 0xFFFFFFFFFFFFFFFF

def popcnt64(x: int) -> int:
	x = uint64(x)
	if hasattr(x, 'bit_count'):
		return x.bit_count()
	else:
		count = 0
		while x:
			x &= x - 1
			count += 1
		return count

def signal_handler(sig: int, frame):
	if sig == SIGINT:
		exit(0)

def dump_traceback() -> str:
	print(format_exc())

class _ArgumentParserBase(ArgumentParser):
	DELIMITER = '\n%s\n\n' % ('-' * 64)

	def __init__(self, **kwargs):
		# Don't add an automatic help argument.
		kwargs['add_help'] = False

		super().__init__(**kwargs)

	def format_help(self):
		formatter = self._get_formatter()

		# Print program title.
		if self.description:
			formatter.add_text(self.description)
			formatter.add_text(_ArgumentParserBase.DELIMITER)

		# Print basic usage.
		formatter.add_usage(self.usage, self._actions, self._mutually_exclusive_groups, self.get_usage_heading())

		# Print available actions.
		for action_group in self._action_groups:
			formatter.start_section(action_group.title)
			formatter.add_text(action_group.description)
			formatter.add_arguments(action_group._group_actions)
			formatter.end_section()

		# Print additional help for each action.
		extra_help = self.get_extra_help()
		if extra_help:
			formatter.add_text(_ArgumentParserBase.DELIMITER + _ArgumentParserBase.DELIMITER.join(extra_help))

		# Print epilog if needed.
		if self.epilog:
			formatter.add_text(_ArgumentParserBase.DELIMITER + self.epilog)

		return formatter.format_help()

	def get_usage_heading(self):
		return 'usage: '

	def get_extra_help(self):
		return []

	def error(self, message):
		self.exit(2, f'error: {message}\n')

class _CmdLineSubParser(_ArgumentParserBase):
	def __init__(self, **kwargs):
		# XXX: Reuse usage parameter to hold header, then remove it to perform standard usage formatting.
		self.usage_heading = kwargs['usage']
		kwargs['usage'] =  None

		super().__init__(**kwargs)

		# Display help argument in common usage only.
		self.add_argument('-h', '--help', action = 'help', help = SUPPRESS)

	def get_usage_heading(self):
		usage_heading = super().get_usage_heading()
		if self.usage_heading is not None:
			usage_heading = '\n'.join([self.usage_heading, usage_heading])
		return usage_heading

class CmdLineParser(_ArgumentParserBase):
	def __init__(self, title, prog = __package__):
		super().__init__(prog = prog, description = title, formatter_class = RawDescriptionHelpFormatter)

		self.add_argument('-h', '--help', action = 'help', help = 'show this help message and exit')
		self.add_argument('-v', '--verbose', action = 'store_true', help = 'more verbose output')
		self.add_argument('-d', '--debug', action = 'store_true', help = 'output debug information')

		self.__subparsers = self.add_subparsers(title = 'actions', dest = 'action', required = True, parser_class = _CmdLineSubParser)

	def add_subparser(self, name, description = None):
		subparser = self.__subparsers.add_parser(name, usage = description, description = self.description)
		return subparser

	def parse_args(self):
		if len(argv) <= 1:
			# Print help if no arguments were specified.
			self.print_help()
			exit(0)

		return super().parse_args()

	def get_extra_help(self):
		extra_help = []

		for name, subparser in self.__subparsers._name_parser_map.items():
			# Remove description temporarily to avoid duplicates.
			old_description, subparser.description = self.description, None
			help = subparser.format_help()
			subparser.description = old_description
			extra_help.append(help)

		return extra_help

class ColoredFormatter(Formatter):
	RESET = '\x1b[0m'
	BRIGHT = '\x1b[1m'
	DIM = '\x1b[2m'
	UNDERSCORE = '\x1b[4m'
	BLINK = '\x1b[5m'
	REVERSE = '\x1b[7m'
	HIDDEN = '\x1b[8m'

	FG_BLACK = '\x1b[30m'
	FG_RED = '\x1b[31m'
	FG_GREEN = '\x1b[32m'
	FG_YELLOW = '\x1b[33m'
	FG_BLUE = '\x1b[34m'
	FG_MAGENTA = '\x1b[35m'
	FG_CYAN = '\x1b[36m'
	FG_WHITE = '\x1b[37m'
	FG_GRAY = '\x1b[38m'

	BG_BLACK = '\x1b[40m'
	BG_RED = '\x1b[41m'
	BG_GREEN = '\x1b[42m'
	BG_YELLOW = '\x1b[43m'
	BG_BLUE = '\x1b[44m'
	BG_MAGENTA = '\x1b[45m'
	BG_CYAN = '\x1b[46m'
	BG_WHITE = '\x1b[47m'
	BG_GRAY = '\x1b[48m'

	RESET = '\x1b[0m'

	def __init__(self, fmt: str = r'%(asctime)s: %(message)s', date_fmt: str = r'%y.%m.%d %H:%M:%S'):
		self.formatters = {
			DEBUG: Formatter(ColoredFormatter.FG_GRAY + fmt + ColoredFormatter.RESET, date_fmt),
			INFO: Formatter(ColoredFormatter.FG_GREEN + fmt + ColoredFormatter.RESET, date_fmt),
			WARNING: Formatter(ColoredFormatter.FG_YELLOW + fmt + ColoredFormatter.RESET, date_fmt),
			ERROR: Formatter(ColoredFormatter.FG_RED + fmt + ColoredFormatter.RESET, date_fmt),
			CRITICAL: Formatter(ColoredFormatter.FG_RED + ColoredFormatter.BRIGHT + fmt + ColoredFormatter.RESET, date_fmt),
		}

	def format(self, record: LogRecord) -> str:
		formatter = self.formatters.get(record.levelno, None)
		if not formatter:
			formatter = Formatter()

		return formatter.format(record)

class ShutdownHandler(StreamHandler):
	def emit(self, record: LogRecord) -> None:
		if record.levelno >= CRITICAL:
			exit(1)

def read_binary(file_path: str, size: Optional[int] = None) -> Optional[bytes]:
	try:
		with open(file_path, 'rb') as f:
			if size is not None:
				data = f.read(size)
			else:
				data = f.read()
	except IOError:
		return None
	return data

def write_binary(file_path: str, data: bytes) -> bool:
	try:
		with open(file_path, 'wb') as f:
			f.write(data)
	except IOError:
		return False
	return True
