class PacketScopeError(Exception):
    """Expected, user-facing failure while importing or analyzing data."""


class InputLimitError(PacketScopeError):
    """An input exceeded a configured safety bound."""


class FormatError(PacketScopeError):
    """The input is malformed or does not match the requested format."""
