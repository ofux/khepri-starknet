%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import split_felt
from starkware.cairo.common.uint256 import Uint256, uint256_eq
from starkware.cairo.common.bool import TRUE, FALSE

from utils.target import decode_target, encode_target
from utils.math import felt_to_Uint256

@view
func test_target_genesis{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*
}():
    alloc_locals
    let bits = 0x1d00ffff
    let (local target, overflow : felt) = decode_target(bits)
    let (hi, lo) = split_felt(0x00000000ffff0000000000000000000000000000000000000000000000000000)
    let (is_eq) = uint256_eq(target, Uint256(lo, hi))
    assert TRUE = is_eq
    return ()
end

@view
func test_target{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*
}():
    alloc_locals
    let bits = 0x1729d72d
    let (local target, overflow : felt) = decode_target(bits)
    let (hi, lo) = split_felt(0x00000000000000000029d72d0000000000000000000000000000000000000000)
    let (is_eq) = uint256_eq(target, Uint256(lo, hi))
    assert TRUE = is_eq
    return ()
end

namespace test_internal:
    func test_encode_decode_target{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
        bitwise_ptr : BitwiseBuiltin*,
    }(
        bits : felt,
        expected_decoded_target : felt,
        expected_overflow : felt,
        expected_reencoded_bits : felt,
    ):
        alloc_locals
        let (local uint256_expected_decoded_target : Uint256) = felt_to_Uint256(
            expected_decoded_target
        )
        test_encode_decode_target_Uint256(
            bits, uint256_expected_decoded_target, expected_overflow, expected_reencoded_bits
        )
        return ()
    end

    func test_encode_decode_target_Uint256{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
        bitwise_ptr : BitwiseBuiltin*,
    }(
        bits : felt,
        expected_decoded_target : Uint256,
        expected_overflow : felt,
        expected_reencoded_bits : felt,
    ):
        alloc_locals
        let (local decoded_target : Uint256, overflow : felt) = decode_target(bits)
        let (decoded_are_equal) = uint256_eq(decoded_target, expected_decoded_target)

        with_attr error_message(
                "For target {target}, expected decoded target to be {expected_decoded_target}, got {decoded_target}"):
            assert decoded_are_equal = TRUE
        end
        with_attr error_message(
                "For target {target}, expected overflow to be {expected_overflow}, got {overflow}"):
            assert expected_overflow = overflow
        end

        let (local reencoded_bits : felt) = encode_target(decoded_target)

        with_attr error_message(
                "For target {target}, expected reencoded bits to be {expected_reencoded_bits}, got {reencoded_bits}"):
            assert expected_reencoded_bits = reencoded_bits
        end

        if overflow == TRUE:
            return ()
        end

        return ()
    end
end

@view
func test_encode_decode_target{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*
}():
    alloc_locals
    test_internal.test_encode_decode_target(0, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x00123456, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x01003456, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x02000056, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x03000000, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x04000000, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x00923456, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x01803456, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x02800056, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x03800000, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x04800000, 0, FALSE, 0)
    test_internal.test_encode_decode_target(0x01003456, 0, FALSE, 0)

    test_internal.test_encode_decode_target(0x01123456, 0x00000012, FALSE, 0x01120000)
    test_internal.test_encode_decode_target(0x02123456, 0x00001234, FALSE, 0x02123400)
    test_internal.test_encode_decode_target(0x03123456, 0x00123456, FALSE, 0x03123456)
    test_internal.test_encode_decode_target(0x04123456, 0x12345600, FALSE, 0x04123456)
    test_internal.test_encode_decode_target(0x05009234, 0x92340000, FALSE, 0x05009234)

    # let (local expected_decoded_target : Uint256) = Uint256(high=)
    test_internal.test_encode_decode_target(
        0x20123456,
        0x1234560000000000000000000000000000000000000000000000000000000000,
        FALSE,
        0x20123456,
    )

    let (local target : Uint256, overflow) = decode_target(0xff123456)
    with_attr error_message("For bits 0xff123456, expected overflow to be 1, got {overflow}"):
        assert TRUE = overflow
    end

    # Make sure that we don't generate compacts with the 0x00800000 bit set
    let (local target0x80 : Uint256) = felt_to_Uint256(0x80)
    let (local bits) = encode_target(target0x80)
    with_attr error_message("For target 0x80, expected bits to be 0x02008000U, got {bits}"):
        assert 0x02008000 = bits
    end

    return ()
end
