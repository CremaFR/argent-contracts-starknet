import pytest
import asyncio
import logging
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.business_logic.state.state import BlockInfo
from utils.Signer import Signer
from utils.utilities import deploy, declare, assert_revert, str_to_felt, assert_event_emmited
from utils.TransactionSender import TransactionSender
from starkware.cairo.common.hash_state import compute_hash_on_elements
from starkware.starknet.compiler.compile import get_selector_from_name
from utils.merkle_utils import generate_merkle_proof, generate_merkle_root, get_leaves, verify_merkle_proof

LOGGER = logging.getLogger(__name__)

signer = Signer(123456789987654321)
guardian = Signer(456789987654321123)
guardian_backup = Signer(354523164513454)

session_key = Signer(666666666666666666)
wrong_session_key = Signer(6767676767)

DEFAULT_TIMESTAMP = 1640991600
ESCAPE_SECURITY_PERIOD = 24*7*60*60

VERSION = str_to_felt('0.2.3')

IACCOUNT_ID = 0xf10dbd44


@pytest.fixture(scope='module')
def event_loop():
    return asyncio.new_event_loop()

@pytest.fixture(scope='module')
async def get_starknet():
    starknet = await Starknet.empty()
    return starknet

def update_starknet_block(starknet, block_number=1, block_timestamp=DEFAULT_TIMESTAMP):
    starknet.state.state.block_info = BlockInfo(
        block_number=block_number,
        block_timestamp=block_timestamp,
        gas_price=0,
        sequencer_address=starknet.state.state.block_info.sequencer_address)

def reset_starknet_block(starknet):
    update_starknet_block(starknet=starknet)

@pytest.fixture
async def account_factory(get_starknet):
    starknet = get_starknet
    account = await deploy(starknet, "contracts/ArgentAccount.cairo")
    await account.initialize(signer.public_key, 0).invoke()
    # plugin_class = await declare(starknet, "contracts/plugins/ArgentSecurity.cairo")
    #await account.add_plugin(signer.public_key, 0).invoke()
    #await account.initialize(plugin_class.class_hash, [signer.public_key]).invoke()
    
    return account

@pytest.fixture
async def dapp_factory(get_starknet):
    starknet = get_starknet
    dapp_class = await declare(starknet, "contracts/test/TestDapp.cairo")
    dapp = await deploy(starknet, "contracts/test/TestDapp.cairo")
    return dapp, dapp_class.class_hash

@pytest.fixture
async def dapp_factory2(get_starknet):
    starknet = get_starknet
    dapp2_class = await declare(starknet, "contracts/test/TestDapp.cairo")
    dapp2 = await deploy(starknet, "contracts/test/TestDapp.cairo")
    return dapp2, dapp2_class.class_hash

@pytest.fixture
async def plugin_default_factory(get_starknet):
    starknet = get_starknet
    plugin_default_class = await declare(starknet, "contracts/plugins/ArgentSecurity.cairo")
    return plugin_default_class.class_hash

@pytest.fixture
async def plugin_factory(get_starknet):
    starknet = get_starknet
    plugin_class = await declare(starknet, "contracts/plugins/SessionKey.cairo")
    plugin_class2 = await declare(starknet, "contracts/plugins/SessionKeyMerkle.cairo")
    return plugin_class.class_hash, plugin_class2.class_hash

@pytest.mark.asyncio
async def test_add_plugin(account_factory, plugin_factory):
    account = account_factory
    plugin_class, plugin_class2 = plugin_factory
    sender = TransactionSender(account)

    assert (await account.is_plugin(plugin_class).call()).result.success == (0)
    tx_exec_info = await sender.send_transaction([(account.contract_address, 'add_plugin', [plugin_class])], [signer])
    assert (await account.is_plugin(plugin_class).call()).result.success == (1)

@pytest.mark.asyncio
async def test_call_dapp_with_session_key(account_factory, plugin_factory, dapp_factory, get_starknet):
    account = account_factory
    plugin_class, plugin_class2 = plugin_factory
    dapp, dapp_class = dapp_factory
    starknet = get_starknet
    sender = TransactionSender(account)

    tx_exec_info = await sender.send_transaction([(account.contract_address, 'add_plugin', [plugin_class])], [signer])

    session_token = get_session_token(session_key.public_key, DEFAULT_TIMESTAMP + 10, dapp.contract_address, get_selector_from_name('set_number'))
    assert (await dapp.get_number(account.contract_address).call()).result.number == 0
    update_starknet_block(starknet=starknet, block_timestamp=(DEFAULT_TIMESTAMP))
    tx_exec_info = await sender.send_transaction(
        [
            (account.contract_address, 'use_plugin', [plugin_class, session_key.public_key, DEFAULT_TIMESTAMP + 10, *session_token, dapp.contract_address, get_selector_from_name('set_number')]),
            (dapp.contract_address, 'set_number', [47])
        ], 
        [session_key])

    assert_event_emmited(
        tx_exec_info,
        from_address=account.contract_address,
        name='transaction_executed'
    )

    assert (await dapp.get_number(account.contract_address).call()).result.number == 47

    await assert_revert(sender.send_transaction(
        [
            (account.contract_address, 'use_plugin', [plugin_class, session_key.public_key, DEFAULT_TIMESTAMP + 10, *session_token, dapp.contract_address, get_selector_from_name('set_number')]),
            (dapp.contract_address, 'increase_number', [2])
        ], 
        [session_key]),
        "unauthorised policy"
    )

@pytest.mark.asyncio
async def test_call_dapp_with_merkle_policy(account_factory, plugin_factory, dapp_factory, dapp_factory2, get_starknet):
    account = account_factory
    plugin_class, plugin_class2 = plugin_factory
    dapp, dapp_class = dapp_factory
    dapp2, dapp2_class = dapp_factory2
    starknet = get_starknet
    sender = TransactionSender(account)

    tx_exec_info = await sender.send_transaction([(account.contract_address, 'add_plugin', [plugin_class2])], [signer])
    merkle_leaves = get_leaves(
        [dapp.contract_address, dapp.contract_address, dapp2.contract_address, dapp2.contract_address, dapp2.contract_address],
        [get_selector_from_name('set_number'), get_selector_from_name('set_number_double'), get_selector_from_name('set_number'), get_selector_from_name('set_number_double'), get_selector_from_name('set_number_times3')]
    )    
    leaves = list(map(lambda x: x[0], merkle_leaves))
    root = generate_merkle_root(leaves)
    proof = generate_merkle_proof(leaves, 0)

    session_token = get_session_token_root(session_key.public_key, DEFAULT_TIMESTAMP + 10, root)
    assert (await dapp.get_number(account.contract_address).call()).result.number == 0
    update_starknet_block(starknet=starknet, block_timestamp=(DEFAULT_TIMESTAMP))
    tx_exec_info = await sender.send_transaction(
        [
            (account.contract_address, 'use_plugin', [plugin_class2, session_key.public_key, DEFAULT_TIMESTAMP + 10, session_token[0], session_token[1], root, *proof]),
            (dapp.contract_address, 'set_number', [47])
        ], 
        [session_key])

    assert_event_emmited(
        tx_exec_info,
        from_address=account.contract_address,
        name='transaction_executed'
    )

    assert (await dapp.get_number(account.contract_address).call()).result.number == 47

    await assert_revert(sender.send_transaction(
        [
            (account.contract_address, 'use_plugin', [plugin_class2, session_key.public_key, DEFAULT_TIMESTAMP + 10, session_token[0], session_token[1], dapp.contract_address, get_selector_from_name('set_number')]),
            (dapp.contract_address, 'increase_number', [2])
        ], 
        [session_key]),
        "unauthorised policy"
    )

# Need to take an array of (contract, function)
def get_session_token(key, expires, contract, function):
    session = [
        key,
        expires,
        contract,
        function
    ]
    hash = compute_hash_on_elements(session)
    return signer.sign(hash)

def get_session_token_root(key, expires, root):
    session = [
        key,
        expires,
        root
    ]
    hash = compute_hash_on_elements(session)
    return signer.sign(hash)