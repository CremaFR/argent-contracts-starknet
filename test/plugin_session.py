import pytest
import asyncio
import logging
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.business_logic.state.state import BlockInfo
from utils.Signer import Signer
from utils.utilities import deploy, assert_revert, str_to_felt, assert_event_emmited
from utils.TransactionSender import TransactionSender
from starkware.cairo.common.hash_state import compute_hash_on_elements
from starkware.starknet.compiler.compile import get_selector_from_name

LOGGER = logging.getLogger(__name__)

signer = Signer(123456789987654321)
wrong_signer = Signer(666666666666666666)

session_key = Signer(666666666666666666)
wrong_session_key = Signer(6767676767)

DEFAULT_TIMESTAMP = 1640991600
ESCAPE_SECURITY_PERIOD = 24*7*60*60

VERSION = str_to_felt('0.2.2')

IACCOUNT_ID = 0xf10dbd44


@pytest.fixture(scope='module')
def event_loop():
    return asyncio.new_event_loop()

@pytest.fixture(scope='module')
async def get_starknet():
    starknet = await Starknet.empty()
    return starknet

def update_starknet_block(starknet, block_number=1, block_timestamp=DEFAULT_TIMESTAMP):
    starknet.state.state.block_info = BlockInfo(block_number=block_number, block_timestamp=block_timestamp, gas_price=0)

def reset_starknet_block(starknet):
    update_starknet_block(starknet=starknet)

@pytest.fixture
async def account_factory2(get_starknet):
    starknet = get_starknet
    account = await deploy(starknet, "contracts/ArgentAccount.cairo")
    await account.initialize(signer.public_key, 0).invoke()
    return account

@pytest.fixture
async def account_factory2(get_starknet):
    starknet = get_starknet
    account = await deploy(starknet, "contracts/ArgentAccount.cairo")
    # await account.initialize(signer.public_key, 0).invoke()
    return account

@pytest.fixture
async def dapp_factory(get_starknet):
    starknet = get_starknet
    dapp = await deploy(starknet, "contracts/test/TestDapp.cairo")
    return dapp

@pytest.fixture
async def plugin_factory(get_starknet):
    starknet = get_starknet
    plugin_session = await deploy(starknet, "contracts/SessionKey.cairo")
    return plugin_session

@pytest.fixture
async def plugin_factory2(get_starknet):
    starknet = get_starknet
    plugin_session = await deploy(starknet, "contracts/DefaultSigner.cairo")
    return plugin_session

@pytest.fixture
async def plugin_factory3(get_starknet):
    starknet = get_starknet
    plugin_session = await deploy(starknet, "contracts/SignerLimited.cairo")
    return plugin_session

@pytest.mark.asyncio
async def test_add_plugin(account_factory, plugin_factory):
    account = account_factory
    plugin = plugin_factory
    sender = TransactionSender(account)

    assert (await account.is_plugin(plugin.contract_address).call()).result.success == (0)
    tx_exec_info = await sender.send_transaction([(account.contract_address, 'add_plugin', [plugin.contract_address])], [signer])
    assert (await account.is_plugin(plugin.contract_address).call()).result.success == (1)

@pytest.mark.asyncio
async def test_call_dapp_with_session_key(account_factory, plugin_factory, dapp_factory, get_starknet):
    account = account_factory
    plugin = plugin_factory
    dapp = dapp_factory
    starknet = get_starknet
    sender = TransactionSender(account)

    tx_exec_info = await sender.send_transaction([(account.contract_address, 'add_plugin', [plugin.contract_address])], [signer])

    session_token = get_session_token(session_key.public_key, DEFAULT_TIMESTAMP + 10)
    assert (await dapp.get_number(account.contract_address).call()).result.number == 0
    update_starknet_block(starknet=starknet, block_timestamp=(DEFAULT_TIMESTAMP))
    tx_exec_info = await sender.send_transaction(
        [
            (account.contract_address, 'use_plugin', [plugin.contract_address, session_key.public_key, DEFAULT_TIMESTAMP + 10, session_token[0], session_token[1]]),
            (dapp.contract_address, 'set_number', [47])
        ], 
        [session_key])

    assert_event_emmited(
        tx_exec_info,
        from_address=account.contract_address,
        name='transaction_executed'
    )

    assert (await dapp.get_number(account.contract_address).call()).result.number == 47

@pytest.mark.asyncio
async def test_default_plugin(account_factory2, plugin_factory, plugin_factory2, dapp_factory, get_starknet):
    account = account_factory2
    plugin = plugin_factory
    SignerPlugin = plugin_factory2
    dapp = dapp_factory
    starknet = get_starknet
    sender = TransactionSender(account)

    #tx_exec_info = await sender.send_transaction([(account.contract_address, 'initialize', [plugin.contract_address, signer.public_key])], [signer])
    await account.initialize(SignerPlugin.contract_address, [signer.public_key]).invoke()
    tx_exec_info = await sender.send_transaction([(account.contract_address, 'add_plugin', [plugin.contract_address])], [signer])
    session_token = get_session_token(session_key.public_key, DEFAULT_TIMESTAMP + 10)
    update_starknet_block(starknet=starknet, block_timestamp=(DEFAULT_TIMESTAMP))
   
    # should throw when calling initialize with another plugin
    await assert_revert(
        account.initialize(plugin.contract_address, [signer.public_key]).invoke(),
        "already initialized"
    )
    
    assert (await dapp.get_number(account.contract_address).call()).result.number == 0
    
    # Use default Plugin by calling it explicitly
    tx_exec_info = await sender.send_transaction(
        [
            (account.contract_address, 'use_plugin', [SignerPlugin.contract_address]),
            (dapp.contract_address, 'set_number', [47])
        ], 
        [signer])

    assert_event_emmited(
        tx_exec_info,
        from_address=account.contract_address,
        name='transaction_executed'
    )

    assert (await dapp.get_number(account.contract_address).call()).result.number == 47

    # Use default Plugin without calling it
    tx_exec_info = await sender.send_transaction(
        [(dapp.contract_address, 'set_number', [69])], 
        [signer]
    )

    assert_event_emmited(
        tx_exec_info,
        from_address=account.contract_address,
        name='transaction_executed'
    )

    assert (await dapp.get_number(account.contract_address).call()).result.number == 69

 
    # Use a session key plugin
    tx_exec_info = await sender.send_transaction(
        [
            (account.contract_address, 'use_plugin', [plugin.contract_address, session_key.public_key, DEFAULT_TIMESTAMP + 10, session_token[0], session_token[1]]),
            (dapp.contract_address, 'set_number', [420])
        ], 
        [session_key])

    assert_event_emmited(
        tx_exec_info,
        from_address=account.contract_address,
        name='transaction_executed'
    )

    assert (await dapp.get_number(account.contract_address).call()).result.number == 420

@pytest.mark.asyncio
async def test_limited_plugin(account_factory2, plugin_factory2, plugin_factory3, dapp_factory, get_starknet):
    account = account_factory2
    SignerPlugin = plugin_factory2
    SignerLimitedPlugin = plugin_factory3
    dapp = dapp_factory
    starknet = get_starknet
    sender = TransactionSender(account)

    #tx_exec_info = await sender.send_transaction([(account.contract_address, 'initialize', [plugin.contract_address, signer.public_key])], [signer])
    await account.initialize(SignerLimitedPlugin.contract_address, [signer.public_key]).invoke()
    tx_exec_info = await sender.send_transaction([(account.contract_address, 'add_plugin', [SignerPlugin.contract_address])], [signer])
    assert (await dapp.get_number(account.contract_address).call()).result.number == 0
    
    # Use default Plugin should revert forbid operation
    await assert_revert(
        sender.send_transaction(
            [
                (account.contract_address, 'use_plugin', [SignerLimitedPlugin.contract_address]),
                (dapp.contract_address, 'set_number', [69])
            ],                 
            [signer]
        )
    )

    # Use default Plugin should revert forbid operation
    await assert_revert(
        sender.send_transaction(
            [
                (dapp.contract_address, 'set_number', [69])
            ],                 
            [signer]
        )
    )

    #assert (await dapp.get_number(account.contract_address).call()).result.number == 69

    # Use default Plugin by calling it explicitly
    tx_exec_info = await sender.send_transaction(
        [
            (account.contract_address, 'use_plugin', [SignerPlugin.contract_address]),
            (dapp.contract_address, 'set_number', [47])
        ], 
        [signer])

    assert_event_emmited(
        tx_exec_info,
        from_address=account.contract_address,
        name='transaction_executed'
    )

    assert (await dapp.get_number(account.contract_address).call()).result.number == 47

    
@pytest.mark.asyncio
async def test_selector(get_starknet):
    starknet = get_starknet
    selector = get_selector_from_name('set_number')

    LOGGER.info(selector)

def get_session_token(key, expires):
    session = [
        key,
        expires
    ]
    hash = compute_hash_on_elements(session)
    return signer.sign(hash)
