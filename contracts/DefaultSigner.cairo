%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.math import (assert_not_equal, assert_not_zero, assert_nn)
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.starknet.common.syscalls import (
    call_contract, delegate_call, get_tx_info, get_contract_address, get_caller_address, get_block_timestamp
)

const CHANGE_SIGNER_SELECTOR = 1540130945889430637313403138889853410180247761946478946165786566748520529557
const CHANGE_GUARDIAN_SELECTOR = 1374386526556551464817815908276843861478960435557596145330240747921847320237
const TRIGGER_ESCAPE_GUARDIAN_SELECTOR = 73865429733192804476769961144708816295126306469589518371407068321865763651
const TRIGGER_ESCAPE_SIGNER_SELECTOR = 651891265762986954898774236860523560457159526623523844149280938288756256223
const ESCAPE_GUARDIAN_SELECTOR = 1662889347576632967292303062205906116436469425870979472602094601074614456040
const ESCAPE_SIGNER_SELECTOR = 578307412324655990419134484880427622068887477430675222732446709420063579565
const CANCEL_ESCAPE_SELECTOR = 992575500541331354489361836180456905167517944319528538469723604173440834912

const ESCAPE_SECURITY_PERIOD = 7*24*60*60 # set to e.g. 7 days in prod

const ESCAPE_TYPE_GUARDIAN = 0
const ESCAPE_TYPE_SIGNER = 1

const ERC165_ACCOUNT_INTERFACE = 0xf10dbd44

const TRUE = 1
const FALSE = 0

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

struct Escape:
    member active_at: felt
    member type: felt
end

####################
# STORAGE VARIABLES
####################
@storage_var
func _signer() -> (res: felt):
end

@storage_var
func _guardian() -> (res: felt):
end

@storage_var
func _guardian_backup() -> (res: felt):
end

@storage_var
func _escape() -> (res: Escape):
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
    return ()
end


@view
func plugin_call_used{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (number_of_call_param_used: felt):
    return (0)
end

####################
# EXTERNAL FUNCTIONS
####################
@external
func write{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(        
        plugin_data_len: felt,
        plugin_data: felt*
    ) -> ():
    alloc_locals
    let address = [plugin_data]
    _signer.write(address)
    return ()
end

@external
func validate{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*,
    } (
        plugin_data_len: felt,
        plugin_data: felt*,
        call_array_len: felt,
        call_array: CallArray*,
        calldata_len: felt,
        calldata: felt*
    ) -> ():
    alloc_locals

    let (calls : Call*) = alloc()
    from_call_array_to_call(call_array_len, call_array, calldata, calls)
    let calls_len = call_array_len

    # if no more calls
    let (tx_info) = get_tx_info()

    if calls_len == 1:
        if calls[0].to == tx_info.account_contract_address:
            tempvar signer_condition = (calls[0].selector - ESCAPE_GUARDIAN_SELECTOR) * (calls[0].selector - TRIGGER_ESCAPE_GUARDIAN_SELECTOR)
            tempvar guardian_condition = (calls[0].selector - ESCAPE_SIGNER_SELECTOR) * (calls[0].selector - TRIGGER_ESCAPE_SIGNER_SELECTOR)
            if signer_condition == 0:
                # validate signer signature
                validate_signer_signature(tx_info.transaction_hash, tx_info.signature, tx_info.signature_len)
                tempvar syscall_ptr: felt* = syscall_ptr
                tempvar range_check_ptr = range_check_ptr
                tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr  
                tempvar ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr
                jmp exit
            else:
                tempvar syscall_ptr: felt* = syscall_ptr
                tempvar range_check_ptr = range_check_ptr
                tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr              
                tempvar ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr              
            end
            if guardian_condition == 0:
                # validate guardian signature
                validate_guardian_signature(tx_info.transaction_hash, tx_info.signature, tx_info.signature_len)
                tempvar syscall_ptr: felt* = syscall_ptr
                tempvar range_check_ptr = range_check_ptr
                tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
                tempvar ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr
                jmp exit              
            else:
                tempvar syscall_ptr: felt* = syscall_ptr
                tempvar range_check_ptr = range_check_ptr
                tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
                tempvar ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr
            end
        else: 
            tempvar syscall_ptr: felt* = syscall_ptr
            tempvar range_check_ptr = range_check_ptr
            tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
            tempvar ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr    
        end
    else:
        # make sure no call is to the account
        assert_no_self_call(tx_info.account_contract_address, calls_len, calls)
        tempvar syscall_ptr: felt* = syscall_ptr
        tempvar range_check_ptr = range_check_ptr
        tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
        tempvar ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr  
    end

    # validate signer and guardian signatures    
    validate_signer_signature(tx_info.transaction_hash, tx_info.signature, tx_info.signature_len)   
    validate_guardian_signature(tx_info.transaction_hash, tx_info.signature + 2, tx_info.signature_len - 2)  
    tempvar syscall_ptr: felt* = syscall_ptr
    tempvar range_check_ptr = range_check_ptr
    tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
    tempvar ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr
    exit:
    return ()
end

func assert_no_self_call(
        self: felt,
        calls_len: felt,
        calls: Call*
    ):
    if calls_len == 0:
        return ()
    end
    assert_not_zero(calls[0].to - self)
    assert_no_self_call(self, calls_len - 1, calls + Call.SIZE)
    return()
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

func validate_signer_signature{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        message: felt, 
        signatures: felt*,
        signatures_len: felt
    ) -> ():
    with_attr error_message("signer signature invalid"):
        assert_nn(signatures_len - 2)
        let (signer) = _signer.read()
        verify_ecdsa_signature(
            message=message,
            public_key=signer,
            signature_r=signatures[0],
            signature_s=signatures[1])
    end
    return()
end

func validate_guardian_signature{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        message: felt,
        signatures: felt*,
        signatures_len: felt
    ) -> ():
    alloc_locals
    let (guardian) = _guardian.read()
    if guardian == 0:
        return()
    else:
        with_attr error_message("guardian signature invalid"):
            if signatures_len == 2:
                # must be signed by guardian
                verify_ecdsa_signature(
                    message=message,
                    public_key=guardian,
                    signature_r=signatures[0],
                    signature_s=signatures[1])
                tempvar syscall_ptr: felt* = syscall_ptr
                tempvar range_check_ptr = range_check_ptr
                tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
            else:
                # must be signed by guardian_backup
                assert signatures_len = 4
                assert (signatures[0] + signatures[1]) = 0
                let (guardian_backup) = _guardian_backup.read()
                verify_ecdsa_signature(
                    message=message,
                    public_key=guardian_backup,
                    signature_r=signatures[2],
                    signature_s=signatures[3])
                tempvar syscall_ptr: felt* = syscall_ptr
                tempvar range_check_ptr = range_check_ptr
                tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
            end
        end
        return()
    end
end