const std = @import("std");

pub const ParseError = error{
    TooShort,
    InvalidHeader,
    UnsupportedProtocol,
};
