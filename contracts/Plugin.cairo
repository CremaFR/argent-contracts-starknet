%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.math import (assert_not_equal, assert_not_zero)
from starkware.starknet.common.syscalls import (get_caller_address)
from starkware.cairo.common.alloc import alloc

#from contracts.ArgentAccount import (from_call_array_to_call)

const TRUE = 1
const FALSE = 0

const RETRY = 2
const OK = 1
const FAIL = 0

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
func restricted_addresses(address: felt) -> (is_restricted_bool: felt):
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
    let (is_allowed) = restricted_addresses.read(address)
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
func add_restricted_address{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(address: felt) -> ():
     # only admin can call this function
    is_admin()
    
    restricted_addresses.write(address, TRUE)
    return ()
end

@external
func remove_restricted_address{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(address: felt) -> ():
     # only admin can call this function
    is_admin()

    restricted_addresses.write(address, FALSE)
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
       return (OK)
    end
    
    # do the current call
    let this_call: Call = [calls]

    let (is_call_authorized) = is_address_restricted(this_call.to)

    if is_call_authorized == 0:
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
        assert_not_equal(caller_address, current_admin)
    end

    return (TRUE)
end
