%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.math import assert_not_zero, assert_le, assert_nn
from starkware.starknet.common.syscalls import (
    call_contract, get_tx_info, delegate_call, get_contract_address, get_caller_address, get_block_timestamp
)
from starkware.cairo.common.hash_state import (
    hash_init, hash_finalize, hash_update, hash_update_single
)

from contracts.Upgradable import _set_implementation

@contract_interface
namespace IAccount:
    func supportsInterface(interfaceId: felt) -> (success : felt):
    end
end

@contract_interface
namespace IPlugin:
    # Method to call during validation
    func validate(
        plugin_data_len: felt,
        plugin_data: felt*,
        call_array_len: felt,
        call_array: CallArray*,
        calldata_len: felt,
        calldata: felt*
    ):
    end

    # Method to write data during Init (delegate call)
    func write(
        plugin_data_len: felt,
        plugin_data: felt*,
    ):
    end

end

####################
# CONSTANTS
####################

const VERSION = '0.2.2'

const CHANGE_SIGNER_SELECTOR = 1540130945889430637313403138889853410180247761946478946165786566748520529557
const CHANGE_GUARDIAN_SELECTOR = 1374386526556551464817815908276843861478960435557596145330240747921847320237
const TRIGGER_ESCAPE_GUARDIAN_SELECTOR = 73865429733192804476769961144708816295126306469589518371407068321865763651
const TRIGGER_ESCAPE_SIGNER_SELECTOR = 651891265762986954898774236860523560457159526623523844149280938288756256223
const ESCAPE_GUARDIAN_SELECTOR = 1662889347576632967292303062205906116436469425870979472602094601074614456040
const ESCAPE_SIGNER_SELECTOR = 578307412324655990419134484880427622068887477430675222732446709420063579565
const CANCEL_ESCAPE_SELECTOR = 992575500541331354489361836180456905167517944319528538469723604173440834912
const USE_PLUGIN_SELECTOR = 1121675007639292412441492001821602921366030142137563176027248191276862353634
const USE_PLUGIN_UPDATE_SELECTOR = 1450767156438606126731669319388422627287833153702538593859922833278978281744

const ESCAPE_SECURITY_PERIOD = 7*24*60*60 # set to e.g. 7 days in prod

const ESCAPE_TYPE_GUARDIAN = 0
const ESCAPE_TYPE_SIGNER = 1

const ERC165_ACCOUNT_INTERFACE = 0xf10dbd44

const TRUE = 1
const FALSE = 0

####################
# STRUCTS
####################

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

struct Escape:
    member active_at: felt
    member type: felt
end

####################
# EVENTS
####################

@event
func account_upgraded(new_implementation: felt):
end

@event
func transaction_executed(hash: felt, response_len: felt, response: felt*):
end

####################
# STORAGE VARIABLES
####################

@storage_var
func _current_nonce() -> (res: felt):
end

@storage_var
func _default_plugin() -> (res: felt):
end

@storage_var
func _plugins(plugin: felt) -> (res: felt):
end

@storage_var
func _guardian() -> (res: felt):
end

@storage_var
func _signer() -> (res: felt):
end


####################
# EXTERNAL FUNCTIONS
####################

@view
func get_guardian{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } () -> (guardian: felt):
    let (res) = _guardian.read()
    return (guardian=res)
end

@view
func get_signer{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } () -> (signer: felt):
    let (res) = _signer.read()
    return (signer=res)
end

@external
func initialize{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        plugin: felt,
        plugin_data_len: felt,
        plugin_data: felt*

    ):
    alloc_locals

    # check that we are not already initialized
    let (current_plugin) = _default_plugin.read()
    with_attr error_message("already initialized"):
        assert current_plugin = 0
    end
    # check that the target signer is not zero
    with_attr error_message("signer cannot be null"):
        assert_not_zero(plugin)
    end
    
    # initialize the contract
    IPlugin.delegate_write(
        contract_address=plugin,
        plugin_data_len=plugin_data_len,
        plugin_data=plugin_data
    )

    # write twice the plugin in case someone wants to call the default plugin specifically ??
    _plugins.write(plugin, 1)
    _default_plugin.write(plugin)
    
    return ()
end

@external
@raw_output
func __execute__{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        call_array_len: felt,
        call_array: CallArray*,
        calldata_len: felt,
        calldata: felt*,
        nonce: felt
    ) -> (
        retdata_size: felt,
        retdata: felt*
    ):
    alloc_locals

    # validate and bump nonce
    validate_and_bump_nonce(nonce)

    ############### TMP #############################
    # parse inputs to an array of 'Call' struct
    let (calls : Call*) = alloc()
    from_call_array_to_call(call_array_len, call_array, calldata, calls)
    let calls_len = call_array_len
    #################################################

    # get the tx info
    let (tx_info) = get_tx_info()

    if calls[0].selector - USE_PLUGIN_SELECTOR == 0:
        # validate with plugin
        let plugin = calldata[call_array[0].data_offset]
        validate_with_plugin(plugin, call_array_len, call_array, calldata_len, calldata)
        jmp do_execute
    else:
        let (plugin) = _default_plugin.read()
        validate_with_default_plugin(plugin, call_array_len, call_array, calldata_len, calldata)
        jmp do_execute
    end

    # execute calls
    do_execute:
    local ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr
    local syscall_ptr: felt* = syscall_ptr
    local range_check_ptr = range_check_ptr
    local pedersen_ptr: HashBuiltin* = pedersen_ptr
    let (response : felt*) = alloc()
    local response_len
    let (plugin_address) = _default_plugin.read()
     if calls[0].selector - USE_PLUGIN_UPDATE_SELECTOR + (calls[0].to - plugin_address) == 0:
        # could call execute_delegate_default_plugin 
        let (res) = execute_delegate_default_plugin(calls_len, calls, response)
        assert response_len = res
        jmp exit
    end
    if calls[0].selector - USE_PLUGIN_SELECTOR == 0:
        # could call execute_with_plugin 
        let (res) = execute_list(calls_len - 1, calls + Call.SIZE, response)
        assert response_len = res
        jmp exit
    end
    let (res) = execute_list(calls_len, calls, response)
    assert response_len = res
    # emit event
    exit:
    transaction_executed.emit(hash=tx_info.transaction_hash, response_len=response_len, response=response)
    return (retdata_size=response_len, retdata=response)
end

###### PLUGIN #######

@external
func add_plugin{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        plugin: felt
    ):
    # only called via execute
    assert_only_self()

    # change signer
    with_attr error_message("plugin cannot be null"):
        assert_not_zero(plugin)
    end
    _plugins.write(plugin, 1)
    return()
end

@view
func is_plugin{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (plugin: felt) -> (success: felt):
    let (res) = _plugins.read(plugin)
    return (success=res)
end

func validate_with_plugin{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        plugin: felt,
        call_array_len: felt,
        call_array: CallArray*,
        calldata_len: felt,
        calldata: felt*
    ):
    alloc_locals

    let (is_plugin) = _plugins.read(plugin)
    assert_not_zero(is_plugin)

    IPlugin.delegate_validate(
        contract_address=plugin,
        plugin_data_len=call_array[0].data_len - 1,
        plugin_data=calldata + call_array[0].data_offset + 1,
        call_array_len=call_array_len - 1,
        call_array=call_array + CallArray.SIZE,
        calldata_len=calldata_len - call_array[0].data_len,
        calldata=calldata + call_array[0].data_offset + call_array[0].data_len)
    return()
end

func validate_with_default_plugin{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        plugin: felt,
        call_array_len: felt,
        call_array: CallArray*,
        calldata_len: felt,
        calldata: felt*
    ):
    alloc_locals

    let (is_plugin) = _plugins.read(plugin)
    assert_not_zero(is_plugin)

    IPlugin.delegate_validate(
        contract_address=plugin,
        plugin_data_len=call_array[0].data_len - 1,
        plugin_data=calldata + call_array[0].data_offset + 1,
        call_array_len=call_array_len,
        call_array=call_array,
        calldata_len=calldata_len,
        calldata=calldata)
    return()
end

######################

@external
func upgrade{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        implementation: felt
    ):
    # only called via execute
    assert_only_self()
    # make sure the target is an account
    with_attr error_message("implementation invalid"):
        let (success) = IAccount.supportsInterface(contract_address=implementation, interfaceId=ERC165_ACCOUNT_INTERFACE)
        assert success = TRUE
    end
    # change implementation
    _set_implementation(implementation)
    account_upgraded.emit(new_implementation=implementation)
    return()
end

@view
func supportsInterface{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        interfaceId: felt
    ) -> (success: felt):

    # 165
    if interfaceId == 0x01ffc9a7:
        return (TRUE)
    end
    # IAccount
    if interfaceId == ERC165_ACCOUNT_INTERFACE:
        return (TRUE)
    end 
    return (FALSE)
end

@view
func get_nonce{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } () -> (nonce: felt):
    let (res) = _current_nonce.read()
    return (nonce=res)
end

@view
func get_version() -> (version: felt):
    return (version=VERSION)
end

####################
# INTERNAL FUNCTIONS
####################

func assert_only_self{
        syscall_ptr: felt*
    } () -> ():
    let (self) = get_contract_address()
    let (caller_address) = get_caller_address()
    with_attr error_message("must be called via execute"):
        assert self = caller_address
    end
    return()
end

func validate_and_bump_nonce{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        message_nonce: felt
    ) -> ():
    let (current_nonce) = _current_nonce.read()
    with_attr error_message("nonce invalid"):
        assert current_nonce = message_nonce
    end
    _current_nonce.write(current_nonce + 1)
    return()
end

# @notice Executes a list of contract calls recursively.
# @param calls_len The number of calls to execute
# @param calls A pointer to the first call to execute
# @param response The array of felt to pupulate with the returned data
# @return response_len The size of the returned data
func execute_list{
        syscall_ptr: felt*
    } (
        calls_len: felt,
        calls: Call*,
        reponse: felt*
    ) -> (
        response_len: felt,
    ):
    alloc_locals

    # if no more calls
    if calls_len == 0:
       return (0)
    end
    
    # do the current call
    let this_call: Call = [calls]
    let res = call_contract(
        contract_address=this_call.to,
        function_selector=this_call.selector,
        calldata_size=this_call.calldata_len,
        calldata=this_call.calldata
    )
    # copy the result in response
    memcpy(reponse, res.retdata, res.retdata_size)
    # do the next calls recursively
    let (response_len) = execute_list(calls_len - 1, calls + Call.SIZE, reponse + res.retdata_size)
    return (response_len + res.retdata_size)
end

# POC - todo rewrite for only call
func execute_delegate_default_plugin{
        syscall_ptr: felt*
    } (
        calls_len: felt,
        calls: Call*,
        reponse: felt*
    ) -> (
        response_len: felt,
    ):
    alloc_locals

    # if no more calls
    if calls_len == 0:
       return (0)
    end
    
    # do the current call
    let this_call: Call = [calls]
    let res = delegate_call(
        contract_address=this_call.to,
        function_selector=[this_call.calldata],
        calldata_size=this_call.calldata_len -1,
        calldata=this_call.calldata + 1
    )
    # copy the result in response
    memcpy(reponse, res.retdata, res.retdata_size)
    # do the next calls recursively
    let (response_len) = execute_list(calls_len - 1, calls + Call.SIZE, reponse + res.retdata_size)
    return (response_len + res.retdata_size)
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
