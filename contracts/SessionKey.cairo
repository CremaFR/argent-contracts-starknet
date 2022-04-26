%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.math import (assert_not_equal, assert_not_zero)
from starkware.cairo.common.math_cmp import (is_le)
from starkware.starknet.common.syscalls import (get_caller_address, get_block_timestamp)
from starkware.cairo.common.alloc import alloc

const TRUE = 1
const FALSE = 0

const EXECUTE = 3
const RETRY = 2
const FAIL = 1
const OK = 0

struct Call:
    member to: felt
    member selector: felt
    member calldata_len: felt
    member calldata: felt*
end

# Tmp struct introduced while we wait for Cairo
# to support passing `[Call]` to __execute__
struct CallArray:
    member to: felt
    member selector: felt
    member data_offset: felt
    member data_len: felt
end

func from_call_array_to_call{
        syscall_ptr: felt*
    } (
        call_array_len: felt,
        call_array: CallArray*,
        calldata: felt*,
        calls: Call*
    ):
    # if no more calls
    if call_array_len == 0:
       return ()
    end
    
    # parse the current call
    assert [calls] = Call(
            to=[call_array].to,
            selector=[call_array].selector,
            calldata_len=[call_array].data_len,
            calldata=calldata + [call_array].data_offset
        )
    
    # parse the remaining calls recursively
    from_call_array_to_call(call_array_len - 1, call_array + CallArray.SIZE, calldata, calls + Call.SIZE)
    return ()
end


####################
# STORAGE VARIABLES
####################
# Admin address
@storage_var
func admin() -> (res: felt):
end

# List of restricted addresses
@storage_var
func temp_key(address: felt) -> (timestamp: felt):
end

@storage_var
func owner() -> (owner_address : felt):
end

#
# Constructor
#
@constructor
func constructor{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
}():
    let (user) = get_caller_address()
    admin.write(value=user)
    return ()
end

####################
# EXTERNAL FUNCTIONS
####################
#
# Getter
#
@view
func get_admin{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (symbol: felt):
    let (current_admin) = admin.read()
    return (current_admin)
end

@view
func is_address_restricted{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(address: felt) -> (symbol: felt):
    let (is_allowed) = temp_key.read(address)
    return (is_allowed)
end

@view
func plugin_call_used{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (number_of_call_param_used: felt):
    return (0)
end
    

#
# Setter
#
@external
func set_admin{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(new_admin: felt) -> ():
    # only admin can call this function
    is_admin()

    admin.write(new_admin)
    return ()
end

@external
func add_session_key{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(address: felt, duration: felt) -> ():
     # only admin can call this function
    is_admin()
    let (block_timestamp) = get_block_timestamp()
    temp_key.write(address, block_timestamp + duration)
    return ()
end

@external
func remove_session_key{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(address: felt) -> ():
     # only admin can call this function
    is_admin()

    let (block_timestamp) = get_block_timestamp()
    temp_key.write(address, 0) 
    return ()
end

@external
func probe{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        call_array_len: felt,
        call_array: CallArray*,
        calldata_len: felt,
        calldata: felt*,
        plugin_offset: felt,
        plugin_total: felt,
    ) -> (
        response_status: felt,
    ):
    alloc_locals

    let (calls : Call*) = alloc()
    from_call_array_to_call(call_array_len, call_array, calldata, calls)
    let calls_len = call_array_len
    # if no more calls
    if call_array_len == 0:
       return (EXECUTE)
    end
    
    # do the current call
    let this_call: Call = [calls]

    let (is_call_restricted) = is_address_restricted(this_call.to)

    if is_call_restricted == 1:
        return (response_status=FAIL)
    else:
        let (response) = probe(call_array_len - 1, call_array + Call.SIZE, calldata_len, calldata, plugin_offset, plugin_total)
        return (response_status=response)
    end
end


#
# Utils function
#

# Verifies that value != 0. The proof will fail otherwise.
func is_admin{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (is_admin: felt):
    let (caller_address) = get_caller_address()
    let (current_admin) = get_admin()

    with_attr error_message("You're not allowed to call this function"):
        assert caller_address = current_admin
    end

    return (TRUE)
end
