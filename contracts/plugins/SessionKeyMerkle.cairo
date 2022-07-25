%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.hash_state import (
    HashState, hash_finalize, hash_init, hash_update, hash_update_single)
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math_cmp import is_le_felt
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_not_zero, assert_nn
from starkware.starknet.common.syscalls import (
    call_contract, get_tx_info, get_contract_address, get_caller_address, get_block_timestamp)
#from starkware.cairo.common.dict import dict_new, dict_read, dict_write

@contract_interface
namespace IAccount:
    func is_valid_signature(hash: felt, sig_len: felt, sig: felt*):
    end 
    func validate_signer_signature(message: felt, signatures_len: felt, signatures: felt*):
    end
end

struct CallArray:
    member to: felt
    member selector: felt
    member data_offset: felt
    member data_len: felt
end

struct StarkNet_Domain:
    member name : felt
    member version : felt
    member chain_id : felt
end

struct Policy:
    member contract : felt
    member function : felt
end

struct Session:
    member key : felt
    member validity : felt
    member policy_len : felt
    member policy : felt*
end

# only for tmp storage todo remove??
@storage_var
func _policy_hash(hash: felt) -> (res: felt):
end

@external
func validate{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        plugin_data_len: felt,
        plugin_data: felt*,
        call_array_len: felt,
        call_array: CallArray*,
        calldata_len: felt,
        calldata: felt*
    ):
    alloc_locals
    
    # get the tx info
    let (tx_info) = get_tx_info()

    # check is the session has expired
    let session_expires = [plugin_data + 1]
    with_attr error_message("session expired"):
        let (now) = get_block_timestamp()
        assert_nn(session_expires - now)
    end
    # check if the session is approved
    let session_key = [plugin_data]
    let root = [plugin_data + 4]
    # policy is after sessionKey, expiration and sig1 and 2. hence 4
    let (hash) = compute_hash(session_key, session_expires, root)
    with_attr error_message("unauthorised session"):
        IAccount.is_valid_signature(
            contract_address=tx_info.account_contract_address,
            hash=hash,
            sig_len=2,
            sig=plugin_data + 2
        )
    end

    check_policy(call_array_len, call_array, root, plugin_data_len - 5, plugin_data + 5)

    # check if the tx is signed by the session key
    with_attr error_message("session key signature invalid"):
        verify_ecdsa_signature(
            message=tx_info.transaction_hash,
            public_key=session_key,
            signature_r=tx_info.signature[0],
            signature_s=tx_info.signature[1]
        )
    end
    return()
end

# compute hash of (to, selector) to be check against all following calls
func check_policy{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        call_array_len: felt,
        call_array: CallArray*,
        root: felt,
        proof_len: felt,
        proof: felt*
     ):
    alloc_locals

    if call_array_len == 0:
        return()
    end

    assert proof_len = 3
    let (leaf) = hash2{hash_ptr=pedersen_ptr}([call_array].to, [call_array].selector)
    let (proof_valid) = merkle_verify(leaf, root, proof_len, proof)
    assert proof_valid = 1
    return()

end

func compute_hash{pedersen_ptr: HashBuiltin*}(session_key: felt, session_expires: felt, root: felt) -> (hash : felt):
    let hash_ptr = pedersen_ptr
    with hash_ptr:
        let (hash_state_ptr) = hash_init()
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, session_key)
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, session_expires)
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, root)
        let (res) = hash_finalize(hash_state_ptr)
        let pedersen_ptr = hash_ptr
    end
    return (hash=res)
end

func merkle_verify{
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        leaf: felt,
        root: felt,
        proof_len: felt,
        proof: felt*
    ) -> (res: felt):
    let (calc_root) = calc_merkle_root(leaf, proof_len, proof)
    # check if calculated root is equal to expected
    if calc_root == root:
        return (1)
    else:
        return (0)
    end
end

# calculates the merkle root of a given proof
func calc_merkle_root{
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        curr: felt,
        proof_len: felt,
        proof: felt*
    ) -> (res: felt):
    alloc_locals

    if proof_len == 0:
        return (curr)
    end

    local node
    local proof_elem = [proof]
    let (le) = is_le_felt(curr, proof_elem)
    
    if le == 1:
        let (n) = hash2{hash_ptr=pedersen_ptr}(curr, proof_elem)
        node = n
    else:
        let (n) = hash2{hash_ptr=pedersen_ptr}(proof_elem, curr)
        node = n
    end

    let (res) = calc_merkle_root(node, proof_len-1, proof+1)
    return (res)
end