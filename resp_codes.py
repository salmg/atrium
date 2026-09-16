

class Resp(object):
    SUCCESS = b"\x90\x00"
    SUCCESS_FILE_INFO_AVAILABLE = b"\x61\x15"

    WRONG_LENGTH = b"\x67\x00"
    FILE_NOT_FOUND = b"\x6A\x82"
    FAILURE = b"\x6A\xF0"
