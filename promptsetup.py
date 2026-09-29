import sys
import time
import contextlib
import atexit
import os
import re
import random
from ctypes import byref, Structure, c_char, POINTER, wintypes, LibraryLoader
import ctypes
from msvcrt import get_osfhandle

class WinColor(object):
    BLACK   = 0
    BLUE    = 1
    GREEN   = 2
    CYAN    = 3
    RED     = 4
    MAGENTA = 5
    YELLOW  = 6
    GREY    = 7

class WinStyle(object):
    NORMAL              = 0x00
    BRIGHT              = 0x08
    BRIGHT_BACKGROUND   = 0x80 

class WinTerm(object):
    def __init__(self):
        self._default = GetConsoleScreenBufferInfo(STDOUT).wAttributes
        self.set_attrs(self._default)
        self._default_fore = self._fore
        self._default_back = self._back
        self._default_style = self._style
        self._light = 0
    def get_attrs(self):
        return self._fore + self._back * 16 + (self._style | self._light)
    def set_attrs(self, value):
        self._fore = value & 7
        self._back = (value >> 4) & 7
        self._style = value & (WinStyle.BRIGHT | WinStyle.BRIGHT_BACKGROUND)
    def reset_all(self, on_stderr=None):
        self.set_attrs(self._default)
        self.set_console(attrs=self._default)
        self._light = 0
    def fore(self, fore=None, light=False, on_stderr=False):
        if fore is None:
            fore = self._default_fore
        self._fore = fore
        if light:
            self._light |= WinStyle.BRIGHT
        else:
            self._light &= ~WinStyle.BRIGHT
        self.set_console(on_stderr=on_stderr)
    def back(self, back=None, light=False, on_stderr=False):
        if back is None:
            back = self._default_back
        self._back = back
        if light:
            self._light |= WinStyle.BRIGHT_BACKGROUND
        else:
            self._light &= ~WinStyle.BRIGHT_BACKGROUND
        self.set_console(on_stderr=on_stderr)
    def style(self, style=None, on_stderr=False):
        if style is None:
            style = self._default_style
        self._style = style
        self.set_console(on_stderr=on_stderr)
    def set_console(self, attrs=None, on_stderr=False):
        if attrs is None:
            attrs = self.get_attrs()
        handle = STDOUT
        if on_stderr:
            handle = STDERR
        SetConsoleTextAttribute(handle, attrs)
    def get_position(self, handle):
        position = GetConsoleScreenBufferInfo(handle).dwCursorPosition
        position.X += 1
        position.Y += 1
        return position
    def set_cursor_position(self, position=None, on_stderr=False):
        if position is None:
            return
        handle = STDOUT
        if on_stderr:
            handle = STDERR
        SetConsoleCursorPosition(handle, position)
    def cursor_adjust(self, x, y, on_stderr=False):
        handle = STDOUT
        if on_stderr:
            handle = STDERR
        position = self.get_position(handle)
        adjusted_position = (position.Y + y, position.X + x)
        SetConsoleCursorPosition(handle, adjusted_position, adjust=False)
    def erase_screen(self, mode=0, on_stderr=False):
        handle = STDOUT
        if on_stderr:
            handle = STDERR
        csbi = GetConsoleScreenBufferInfo(handle)
        cells_in_screen = csbi.dwSize.X * csbi.dwSize.Y
        cells_before_cursor = csbi.dwSize.X * csbi.dwCursorPosition.Y + csbi.dwCursorPosition.X
        if mode == 0:
            from_coord = csbi.dwCursorPosition
            cells_to_erase = cells_in_screen - cells_before_cursor
        elif mode == 1:
            from_coord = COORD(0, 0)
            cells_to_erase = cells_before_cursor
        elif mode == 2:
            from_coord = COORD(0, 0)
            cells_to_erase = cells_in_screen
        else:
            return
        FillConsoleOutputCharacter(handle, ' ', cells_to_erase, from_coord)
        FillConsoleOutputAttribute(handle, self.get_attrs(), cells_to_erase, from_coord)
        if mode == 2:
            SetConsoleCursorPosition(handle, (1, 1))
    def erase_line(self, mode=0, on_stderr=False):
        handle = STDOUT
        if on_stderr:
            handle = STDERR
        csbi = GetConsoleScreenBufferInfo(handle)
        if mode == 0:
            from_coord = csbi.dwCursorPosition
            cells_to_erase = csbi.dwSize.X - csbi.dwCursorPosition.X
        elif mode == 1:
            from_coord = COORD(0, csbi.dwCursorPosition.Y)
            cells_to_erase = csbi.dwCursorPosition.X
        elif mode == 2:
            from_coord = COORD(0, csbi.dwCursorPosition.Y)
            cells_to_erase = csbi.dwSize.X
        else:
            return
        FillConsoleOutputCharacter(handle, ' ', cells_to_erase, from_coord)
        FillConsoleOutputAttribute(handle, self.get_attrs(), cells_to_erase, from_coord)
    def set_title(self, title):
        SetConsoleTitle(title)

def enable_vt_processing(fd):
    if windll is None or not winapi_test():
        return False
    try:
        handle = get_osfhandle(fd)
        mode = GetConsoleMode(handle)
        SetConsoleMode(
            handle,
            mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        )
        mode = GetConsoleMode(handle)
        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
            return True
    except (OSError, TypeError):
        return False

STDOUT = -11
STDERR = -12
ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

try:
    windll = LibraryLoader(ctypes.WinDLL)
except (AttributeError, ImportError):
    windll = None
    SetConsoleTextAttribute = lambda *_: None
    winapi_test = lambda *_: None
else:
    COORD = wintypes._COORD
    class CONSOLE_SCREEN_BUFFER_INFO(Structure):
        _fields_ = [
            ("dwSize", COORD),
            ("dwCursorPosition", COORD),
            ("wAttributes", wintypes.WORD),
            ("srWindow", wintypes.SMALL_RECT),
            ("dwMaximumWindowSize", COORD),
        ]
        def __str__(self):
            return '(%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d)' % (
                self.dwSize.Y, self.dwSize.X
                , self.dwCursorPosition.Y, self.dwCursorPosition.X
                , self.wAttributes
                , self.srWindow.Top, self.srWindow.Left, self.srWindow.Bottom, self.srWindow.Right
                , self.dwMaximumWindowSize.Y, self.dwMaximumWindowSize.X
            )
    _GetStdHandle = windll.kernel32.GetStdHandle
    _GetStdHandle.argtypes = [
        wintypes.DWORD,
    ]
    _GetStdHandle.restype = wintypes.HANDLE
    _GetConsoleScreenBufferInfo = windll.kernel32.GetConsoleScreenBufferInfo
    _GetConsoleScreenBufferInfo.argtypes = [
        wintypes.HANDLE,
        POINTER(CONSOLE_SCREEN_BUFFER_INFO),
    ]
    _GetConsoleScreenBufferInfo.restype = wintypes.BOOL
    _SetConsoleTextAttribute = windll.kernel32.SetConsoleTextAttribute
    _SetConsoleTextAttribute.argtypes = [
        wintypes.HANDLE,
        wintypes.WORD,
    ]
    _SetConsoleTextAttribute.restype = wintypes.BOOL
    _SetConsoleCursorPosition = windll.kernel32.SetConsoleCursorPosition
    _SetConsoleCursorPosition.argtypes = [
        wintypes.HANDLE,
        COORD,
    ]
    _SetConsoleCursorPosition.restype = wintypes.BOOL
    _FillConsoleOutputCharacterA = windll.kernel32.FillConsoleOutputCharacterA
    _FillConsoleOutputCharacterA.argtypes = [
        wintypes.HANDLE,
        c_char,
        wintypes.DWORD,
        COORD,
        POINTER(wintypes.DWORD),
    ]
    _FillConsoleOutputCharacterA.restype = wintypes.BOOL
    _FillConsoleOutputAttribute = windll.kernel32.FillConsoleOutputAttribute
    _FillConsoleOutputAttribute.argtypes = [
        wintypes.HANDLE,
        wintypes.WORD,
        wintypes.DWORD,
        COORD,
        POINTER(wintypes.DWORD),
    ]
    _FillConsoleOutputAttribute.restype = wintypes.BOOL
    _SetConsoleTitleW = windll.kernel32.SetConsoleTitleW
    _SetConsoleTitleW.argtypes = [
        wintypes.LPCWSTR
    ]
    _SetConsoleTitleW.restype = wintypes.BOOL
    _GetConsoleMode = windll.kernel32.GetConsoleMode
    _GetConsoleMode.argtypes = [
        wintypes.HANDLE,
        POINTER(wintypes.DWORD)
    ]
    _GetConsoleMode.restype = wintypes.BOOL
    _SetConsoleMode = windll.kernel32.SetConsoleMode
    _SetConsoleMode.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD
    ]
    _SetConsoleMode.restype = wintypes.BOOL
    def _winapi_test(handle):
        csbi = CONSOLE_SCREEN_BUFFER_INFO()
        success = _GetConsoleScreenBufferInfo(
            handle, byref(csbi))
        return bool(success)
    def winapi_test():
        return any(_winapi_test(h) for h in
                   (_GetStdHandle(STDOUT), _GetStdHandle(STDERR)))
    def GetConsoleScreenBufferInfo(stream_id=STDOUT):
        handle = _GetStdHandle(stream_id)
        csbi = CONSOLE_SCREEN_BUFFER_INFO()
        success = _GetConsoleScreenBufferInfo(
            handle, byref(csbi))
        return csbi
    def SetConsoleTextAttribute(stream_id, attrs):
        handle = _GetStdHandle(stream_id)
        return _SetConsoleTextAttribute(handle, attrs)
    def SetConsoleCursorPosition(stream_id, position, adjust=True):
        position = COORD(*position)
        if position.Y <= 0 or position.X <= 0:
            return
        adjusted_position = COORD(position.Y - 1, position.X - 1)
        if adjust:
            sr = GetConsoleScreenBufferInfo(STDOUT).srWindow
            adjusted_position.Y += sr.Top
            adjusted_position.X += sr.Left
        handle = _GetStdHandle(stream_id)
        return _SetConsoleCursorPosition(handle, adjusted_position)
    def FillConsoleOutputCharacter(stream_id, char, length, start):
        handle = _GetStdHandle(stream_id)
        char = c_char(char.encode())
        length = wintypes.DWORD(length)
        num_written = wintypes.DWORD(0)
        success = _FillConsoleOutputCharacterA(
            handle, char, length, start, byref(num_written))
        return num_written.value
    def FillConsoleOutputAttribute(stream_id, attr, length, start):
        handle = _GetStdHandle(stream_id)
        attribute = wintypes.WORD(attr)
        length = wintypes.DWORD(length)
        num_written = wintypes.DWORD(0)
        return _FillConsoleOutputAttribute(
            handle, attribute, length, start, byref(num_written))
    def SetConsoleTitle(title):
        return _SetConsoleTitleW(title)
    def GetConsoleMode(handle):
        mode = wintypes.DWORD()
        success = _GetConsoleMode(handle, byref(mode))
        if not success:
            raise ctypes.WinError()
        return mode.value
    def SetConsoleMode(handle, mode):
        success = _SetConsoleMode(handle, mode)
        if not success:
            raise ctypes.WinError()

CSI = '\033['
OSC = '\033]'
BEL = '\a'

def code_to_chars(code):
    return CSI + str(code) + 'm'

def set_title(title):
    return OSC + '2;' + title + BEL

def clear_screen(mode=2):
    return CSI + str(mode) + 'J'

def clear_line(mode=2):
    return CSI + str(mode) + 'K'

class AnsiCodes(object):
    def __init__(self):
        for name in dir(self):
            if not name.startswith('_'):
                value = getattr(self, name)
                setattr(self, name, code_to_chars(value))

class AnsiCursor(object):
    def UP(self, n=1):
        return CSI + str(n) + 'A'
    def DOWN(self, n=1):
        return CSI + str(n) + 'B'
    def FORWARD(self, n=1):
        return CSI + str(n) + 'C'
    def BACK(self, n=1):
        return CSI + str(n) + 'D'
    def POS(self, x=1, y=1):
        return CSI + str(y) + ';' + str(x) + 'H'

class AnsiFore(AnsiCodes):
    BLACK           = 30
    RED             = 31
    GREEN           = 32
    YELLOW          = 33
    BLUE            = 34
    MAGENTA         = 35
    CYAN            = 36
    WHITE           = 37
    RESET           = 39
    LIGHTBLACK_EX   = 90
    LIGHTRED_EX     = 91
    LIGHTGREEN_EX   = 92
    LIGHTYELLOW_EX  = 93
    LIGHTBLUE_EX    = 94
    LIGHTMAGENTA_EX = 95
    LIGHTCYAN_EX    = 96
    LIGHTWHITE_EX   = 97

class AnsiBack(AnsiCodes):
    BLACK           = 40
    RED             = 41
    GREEN           = 42
    YELLOW          = 43
    BLUE            = 44
    MAGENTA         = 45
    CYAN            = 46
    WHITE           = 47
    RESET           = 49
    LIGHTBLACK_EX   = 100
    LIGHTRED_EX     = 101
    LIGHTGREEN_EX   = 102
    LIGHTYELLOW_EX  = 103
    LIGHTBLUE_EX    = 104
    LIGHTMAGENTA_EX = 105
    LIGHTCYAN_EX    = 106
    LIGHTWHITE_EX   = 107

class AnsiStyle(AnsiCodes):
    BRIGHT    = 1
    DIM       = 2
    NORMAL    = 22
    RESET_ALL = 0

Fore   = AnsiFore()
Back   = AnsiBack()
Style  = AnsiStyle()
Cursor = AnsiCursor()
winterm = None
if windll is not None:
    winterm = WinTerm()

class StreamWrapper(object):
    def __init__(self, wrapped, converter):
        self.__wrapped = wrapped
        self.__convertor = converter
    def __getattr__(self, name):
        return getattr(self.__wrapped, name)
    def __enter__(self, *args, **kwargs):
        return self.__wrapped.__enter__(*args, **kwargs)
    def __exit__(self, *args, **kwargs):
        return self.__wrapped.__exit__(*args, **kwargs)
    def __setstate__(self, state):
        self.__dict__ = state
    def __getstate__(self):
        return self.__dict__
    def write(self, text):
        self.__convertor.write(text)
    def isatty(self):
        stream = self.__wrapped
        if 'PYCHARM_HOSTED' in os.environ:
            if stream is not None and (stream is sys.__stdout__ or stream is sys.__stderr__):
                return True
        try:
            stream_isatty = stream.isatty
        except AttributeError:
            return False
        else:
            return stream_isatty()
    @property
    def closed(self):
        stream = self.__wrapped
        try:
            return stream.closed
        except (AttributeError, ValueError):
            return True

class AnsiToWin32(object):
    ANSI_CSI_RE = re.compile(r'\001?\033\[((?:\d|;)*)([a-zA-Z])\002?')
    ANSI_OSC_RE = re.compile(r'\001?\033\]([^\a]*)(\a)\002?')           
    def __init__(self, wrapped, convert=None, strip=None, autoreset=False):
        self.wrapped = wrapped
        self.autoreset = autoreset
        self.stream = StreamWrapper(wrapped, self)
        on_windows = os.name == 'nt'
        conversion_supported = on_windows and winapi_test()
        try:
            fd = wrapped.fileno()
        except Exception:
            fd = -1
        system_has_native_ansi = not on_windows or enable_vt_processing(fd)
        have_tty = not self.stream.closed and self.stream.isatty()
        need_conversion = conversion_supported and not system_has_native_ansi
        if strip is None:
            strip = need_conversion or not have_tty
        self.strip = strip
        if convert is None:
            convert = need_conversion and have_tty
        self.convert = convert
        self.win32_calls = self.get_win32_calls()
        self.on_stderr = self.wrapped is sys.stderr
    def should_wrap(self):
        return self.convert or self.strip or self.autoreset
    def get_win32_calls(self):
        if self.convert and winterm:
            return {
                AnsiStyle.RESET_ALL: (winterm.reset_all, ),
                AnsiStyle.BRIGHT: (winterm.style, WinStyle.BRIGHT),
                AnsiStyle.DIM: (winterm.style, WinStyle.NORMAL),
                AnsiStyle.NORMAL: (winterm.style, WinStyle.NORMAL),
                AnsiFore.BLACK: (winterm.fore, WinColor.BLACK),
                AnsiFore.RED: (winterm.fore, WinColor.RED),
                AnsiFore.GREEN: (winterm.fore, WinColor.GREEN),
                AnsiFore.YELLOW: (winterm.fore, WinColor.YELLOW),
                AnsiFore.BLUE: (winterm.fore, WinColor.BLUE),
                AnsiFore.MAGENTA: (winterm.fore, WinColor.MAGENTA),
                AnsiFore.CYAN: (winterm.fore, WinColor.CYAN),
                AnsiFore.WHITE: (winterm.fore, WinColor.GREY),
                AnsiFore.RESET: (winterm.fore, ),
                AnsiFore.LIGHTBLACK_EX: (winterm.fore, WinColor.BLACK, True),
                AnsiFore.LIGHTRED_EX: (winterm.fore, WinColor.RED, True),
                AnsiFore.LIGHTGREEN_EX: (winterm.fore, WinColor.GREEN, True),
                AnsiFore.LIGHTYELLOW_EX: (winterm.fore, WinColor.YELLOW, True),
                AnsiFore.LIGHTBLUE_EX: (winterm.fore, WinColor.BLUE, True),
                AnsiFore.LIGHTMAGENTA_EX: (winterm.fore, WinColor.MAGENTA, True),
                AnsiFore.LIGHTCYAN_EX: (winterm.fore, WinColor.CYAN, True),
                AnsiFore.LIGHTWHITE_EX: (winterm.fore, WinColor.GREY, True),
                AnsiBack.BLACK: (winterm.back, WinColor.BLACK),
                AnsiBack.RED: (winterm.back, WinColor.RED),
                AnsiBack.GREEN: (winterm.back, WinColor.GREEN),
                AnsiBack.YELLOW: (winterm.back, WinColor.YELLOW),
                AnsiBack.BLUE: (winterm.back, WinColor.BLUE),
                AnsiBack.MAGENTA: (winterm.back, WinColor.MAGENTA),
                AnsiBack.CYAN: (winterm.back, WinColor.CYAN),
                AnsiBack.WHITE: (winterm.back, WinColor.GREY),
                AnsiBack.RESET: (winterm.back, ),
                AnsiBack.LIGHTBLACK_EX: (winterm.back, WinColor.BLACK, True),
                AnsiBack.LIGHTRED_EX: (winterm.back, WinColor.RED, True),
                AnsiBack.LIGHTGREEN_EX: (winterm.back, WinColor.GREEN, True),
                AnsiBack.LIGHTYELLOW_EX: (winterm.back, WinColor.YELLOW, True),
                AnsiBack.LIGHTBLUE_EX: (winterm.back, WinColor.BLUE, True),
                AnsiBack.LIGHTMAGENTA_EX: (winterm.back, WinColor.MAGENTA, True),
                AnsiBack.LIGHTCYAN_EX: (winterm.back, WinColor.CYAN, True),
                AnsiBack.LIGHTWHITE_EX: (winterm.back, WinColor.GREY, True),
            }
        return dict()
    def write(self, text):
        if self.strip or self.convert:
            self.write_and_convert(text)
        else:
            self.wrapped.write(text)
            self.wrapped.flush()
        if self.autoreset:
            self.reset_all()
    def reset_all(self):
        if self.convert:
            self.call_win32('m', (0,))
        elif not self.strip and not self.stream.closed:
            self.wrapped.write(Style.RESET_ALL)
    def write_and_convert(self, text):
        cursor = 0
        text = self.convert_osc(text)
        for match in self.ANSI_CSI_RE.finditer(text):
            start, end = match.span()
            self.write_plain_text(text, cursor, start)
            self.convert_ansi(*match.groups())
            cursor = end
        self.write_plain_text(text, cursor, len(text))
    def write_plain_text(self, text, start, end):
        if start < end:
            self.wrapped.write(text[start:end])
            self.wrapped.flush()
    def convert_ansi(self, paramstring, command):
        if self.convert:
            params = self.extract_params(command, paramstring)
            self.call_win32(command, params)
    def extract_params(self, command, paramstring):
        if command in 'Hf':
            params = tuple(int(p) if len(p) != 0 else 1 for p in paramstring.split(';'))
            while len(params) < 2:
                params = params + (1,)
        else:
            params = tuple(int(p) for p in paramstring.split(';') if len(p) != 0)
            if len(params) == 0:
                if command in 'JKm':
                    params = (0,)
                elif command in 'ABCD':
                    params = (1,)
        return params
    def call_win32(self, command, params):
        if command == 'm':
            for param in params:
                if param in self.win32_calls:
                    func_args = self.win32_calls[param]
                    func = func_args[0]
                    args = func_args[1:]
                    kwargs = dict(on_stderr=self.on_stderr)
                    func(*args, **kwargs)
        elif command in 'J':
            winterm.erase_screen(params[0], on_stderr=self.on_stderr)
        elif command in 'K':
            winterm.erase_line(params[0], on_stderr=self.on_stderr)
        elif command in 'Hf':
            winterm.set_cursor_position(params, on_stderr=self.on_stderr)
        elif command in 'ABCD':
            n = params[0]
            x, y = {'A': (0, -n), 'B': (0, n), 'C': (n, 0), 'D': (-n, 0)}[command]
            winterm.cursor_adjust(x, y, on_stderr=self.on_stderr)
    def convert_osc(self, text):
        for match in self.ANSI_OSC_RE.finditer(text):
            start, end = match.span()
            text = text[:start] + text[end:]
            paramstring, command = match.groups()
            if command == BEL:
                if paramstring.count(";") == 1:
                    params = paramstring.split(";")
                    if params[0] in '02':
                        winterm.set_title(params[1])
        return text
    def flush(self):
        self.wrapped.flush()

def _wipe_internal_state_for_tests():
    global orig_stdout, orig_stderr
    orig_stdout = None
    orig_stderr = None
    global wrapped_stdout, wrapped_stderr
    wrapped_stdout = None
    wrapped_stderr = None
    global atexit_done
    atexit_done = False
    global fixed_windows_console
    fixed_windows_console = False
    try:
        atexit.unregister(reset_all)
    except AttributeError:
        pass

def reset_all():
    if AnsiToWin32 is not None:
        AnsiToWin32(orig_stdout).reset_all()

def init(autoreset=False, convert=None, strip=None, wrap=True):
    if not wrap and any([autoreset, convert, strip]):
        raise ValueError('wrap=False conflicts with any other arg=True')
    global wrapped_stdout, wrapped_stderr
    global orig_stdout, orig_stderr
    orig_stdout = sys.stdout
    orig_stderr = sys.stderr
    if sys.stdout is None:
        wrapped_stdout = None
    else:
        sys.stdout = wrapped_stdout = \
            wrap_stream(orig_stdout, convert, strip, autoreset, wrap)
    if sys.stderr is None:
        wrapped_stderr = None
    else:
        sys.stderr = wrapped_stderr = \
            wrap_stream(orig_stderr, convert, strip, autoreset, wrap)
    global atexit_done
    if not atexit_done:
        atexit.register(reset_all)
        atexit_done = True

def deinit():
    if orig_stdout is not None:
        sys.stdout = orig_stdout
    if orig_stderr is not None:
        sys.stderr = orig_stderr

def just_fix_windows_console():
    global fixed_windows_console
    if sys.platform != "win32":
        return
    if fixed_windows_console:
        return
    if wrapped_stdout is not None or wrapped_stderr is not None:
        return
    new_stdout = AnsiToWin32(sys.stdout, convert=None, strip=None, autoreset=False)
    if new_stdout.convert:
        sys.stdout = new_stdout
    new_stderr = AnsiToWin32(sys.stderr, convert=None, strip=None, autoreset=False)
    if new_stderr.convert:
        sys.stderr = new_stderr
    fixed_windows_console = True

@contextlib.contextmanager
def colorama_text(*args, **kwargs):
    init(*args, **kwargs)
    try:
        yield
    finally:
        deinit()

def reinit():
    if wrapped_stdout is not None:
        sys.stdout = wrapped_stdout
    if wrapped_stderr is not None:
        sys.stderr = wrapped_stderr

def wrap_stream(stream, convert, strip, autoreset, wrap):
    if wrap:
        wrapper = AnsiToWin32(stream,
            convert=convert, strip=strip, autoreset=autoreset)
        if wrapper.should_wrap():
            stream = wrapper.stream
    return stream

_wipe_internal_state_for_tests()

def sprint(chars, delay=0.05):
    for char in chars:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)

init()

Fore = Fore

# More realistic IP addresses and hostnames
ipaddr = "192.168.1.105"
hostname = "kali"
windows_host = "DESKTOP-7K3J8L2"
mac_host = "MacBook-Pro"
raphos_host = "raphos-dev"

# Kali uses this special symbol in its prompt
kali_symbol = "㉿"  # U+327F Korean standard symbol, used by Kali Linux
ubuntu_symbol = "@"
raphOS_symbol = "⨷"

def get_path_segment(os, ostype=None):
    """Returns a realistic current working directory segment for the prompt."""
    if os == "windows":
        return "C:\\Users\\llmhacker"
    elif os == "mac":
        return "~"
    elif os == "linux":
        if ostype and ostype.lower() == "kali":
            return "~"  # Kali default home
        elif ostype and ostype.lower() == "ubuntu":
            return "~"
        elif ostype and ostype.lower() == "raphos":
            return "~"
    return "~"

def prompt(ipaddr, username, os, ostype=None):
    path = get_path_segment(os, ostype)

    if os == "windows":
        # Realistic PowerShell prompt
        # PS C:\Users\llmhacker> 
        prompt_text = f"PS {path}> "

    elif os == "mac":
        # macOS zsh default prompt (since Catalina):
        # username@hostname ~ %
        prompt_text = f"{Fore.GREEN}{username}{Fore.RESET}@{Fore.YELLOW}{mac_host}{Fore.RESET} {Fore.CYAN}{path}{Fore.RESET} % "

    elif os == "linux":
        if ostype is None:
            raise ValueError("OS Type is not defined")

        ostype = ostype.lower()

        if ostype == "kali":
            shell_symbol = "#"
            prompt_text = (
                f"{Fore.BLUE}┌──({Fore.GREEN}{username}{Fore.RESET}{kali_symbol}"
                f"{Fore.RED}{hostname}{Fore.BLUE})-[{Fore.WHITE}{path}{Fore.BLUE}]\n"
                f"{Fore.BLUE}└─{Fore.GREEN}{shell_symbol}{Fore.RESET} "
            )

        elif ostype == "ubuntu":
            # Standard Ubuntu bash prompt:
            # username@hostname:~$ 
            prompt_text = f"{Fore.GREEN}{username}{Fore.RESET}{ubuntu_symbol}{Fore.RED}{hostname}{Fore.RESET}:{Fore.BLUE}{path}{Fore.RESET}$ "

        elif ostype == "raphos":
            # Custom raphOS prompt - styled like a security-focused distro
            prompt_text = f"{Fore.CYAN}[{Fore.GREEN}{username}{Fore.RED}{raphOS_symbol}{Fore.BLUE}{raphos_host}{Fore.CYAN}]{Fore.YELLOW}{path}{Fore.RESET}> "

        else:
            raise ValueError(f"Unknown OS Type: {ostype}")
    else:
        raise ValueError(f"Could not find the OS type: {os}")

    return prompt_text

if __name__ == "__main__":
    print("=== Windows PowerShell ===")
    print(prompt(ipaddr, "llmhacker", "windows"))

    print("\n=== macOS zsh ===")
    print(prompt(ipaddr, "llmhacker", "mac"))

    print("\n=== Kali Linux (user) ===")
    print(prompt(ipaddr, "llmhacker", "linux", "kali"))

    print("\n=== Kali Linux (root) ===")
    print(prompt(ipaddr, "root", "linux", "kali"))

    print("\n=== Ubuntu ===")
    print(prompt(ipaddr, "llmhacker", "linux", "ubuntu"))

    print("\n=== raphOS ===")
    print(prompt(ipaddr, "llmhacker", "linux", "raphos"))

    print("\n=== Interactive Test ===")
    user_input = input(prompt(ipaddr, "llmhacker", "linux", "kali"))
    print(f"SUCCESS!! You typed: {user_input}")
