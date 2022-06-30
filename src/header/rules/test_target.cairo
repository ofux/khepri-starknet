%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256
from header.library import BlockHeader, block_header_hash_, block_header_
from header.rules.target import target
from bitcoin.params import Params, get_params
from utils.target import decode_target, encode_target
from utils.math import felt_to_Uint256

const TWO_WEEKS = 2 * 7 * 24 * 60 * 60
const RETARGET_HEIGHT = 2016

@view
func test_target_rule_no_retarget{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr
}():
    let (params : Params) = get_params()
    let (previous_target : Uint256) = felt_to_Uint256(42000)
    let (bits) = encode_target(previous_target)

    tempvar last_header : BlockHeader = BlockHeader(
        version=2,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=1000,
        bits=bits,
        nonce=0,
        hash=Uint256(0, 0)
        )

    tempvar header : BlockHeader = BlockHeader(
        version=2,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=last_header.timestamp + 600,
        bits=bits,
        nonce=0,
        hash=Uint256(0, 0)
        )

    target.assert_rule(header, last_header, 10 * RETARGET_HEIGHT - 100, params)

    return ()
end

@view
func test_target_rule_retarget{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    let (params : Params) = get_params()
    let last_height = 10 * RETARGET_HEIGHT - 1
    let (previous_target : Uint256) = felt_to_Uint256(42000)
    let (bits) = encode_target(previous_target)

    tempvar header_2016_away : BlockHeader = BlockHeader(
        version=2,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=1000,
        bits=bits,
        nonce=0,
        hash=Uint256(0, 0)
        )

    block_header_hash_.write(last_height - (RETARGET_HEIGHT - 1), Uint256(1, 1))
    block_header_.write(Uint256(1, 1), header_2016_away)

    tempvar last_header : BlockHeader = BlockHeader(
        version=2,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=header_2016_away.timestamp + TWO_WEEKS * 2,
        bits=bits,
        nonce=0,
        hash=Uint256(0, 0)
        )

    let (expected_target : Uint256) = felt_to_Uint256(84000)  # 42000 * (TWO_WEEKS*2 / TWO_WEEKS)
    let (expected_bits) = encode_target(expected_target)

    tempvar header : BlockHeader = BlockHeader(
        version=2,
        prev_block=Uint256(0, 0),
        merkle_root=Uint256(0, 0),
        timestamp=last_header.timestamp + 600,
        bits=expected_bits,
        nonce=0,
        hash=Uint256(0, 0)
        )

    target.assert_rule(header, last_header, last_height, params)

    return ()
end
