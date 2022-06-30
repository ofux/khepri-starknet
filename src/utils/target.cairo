%lang starknet

from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import unsigned_div_rem, split_felt
from starkware.cairo.common.pow import pow
from starkware.cairo.common.bool import TRUE, FALSE

#
# The "compact" format is a representation of a whole
# number N using an unsigned 32bit number similar to a
# floating point format.
# The most significant 8 bits are the unsigned exponent of base 256.
# This exponent can be thought of as "number of bytes of N".
# The lower 23 bits are the mantissa.
# Bit number 24 (0x800000) represents the sign of N.
# N = (-1^sign) * mantissa * 256^(exponent-3)
#
# Satoshi's original implementation used BN_bn2mpi() and BN_mpi2bn().
# MPI uses the most significant bit of the first byte as sign.
# Thus 0x1234560000 is compact (0x05123456)
# and  0xc0de000000 is compact (0x0600c0de)
#
# Bitcoin only uses this "compact" format for encoding difficulty
# targets, which are unsigned 256bit quantities.  Thus, all the
# complexities of the sign bit and using base 256 are probably an
# implementation accident.
#

func decode_target{range_check_ptr}(bits : felt) -> (res : Uint256, overflow : felt):
    alloc_locals
    let (exponent, _) = unsigned_div_rem(bits, 2 ** 24)
    let (_, local mantissa) = unsigned_div_rem(bits, 2 ** 23)
    let (exp) = pow(256, exponent - 3)
    let tmp = mantissa * exp
    let res_target = split_felt(tmp)
    return (Uint256(res_target.low, res_target.high), FALSE)
end

func encode_target{range_check_ptr}(val : Uint256) -> (bits : felt):
    return (0)
end
