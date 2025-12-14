from solcx import compile_source, install_solc
from web3 import Web3
import json

ganache_url = "http://127.0.0.1:8545"
w3 = Web3(Web3.HTTPProvider(ganache_url))
install_solc("0.8.19")

with open("contracts/PharmaChain.sol", "r") as f:
    sol_source = f.read()

compiled_sol = compile_source(
    sol_source,
    output_values=["abi", "bin"],
    solc_version="0.8.19"
)
contract_id, contract_interface = next(iter(compiled_sol.items()))
abi = contract_interface['abi']
bytecode = contract_interface['bin']

acct = w3.eth.accounts[0]
PharmaChain = w3.eth.contract(abi=abi, bytecode=bytecode)
tx_hash = PharmaChain.constructor().transact({'from': acct})
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

with open("PharmaChain_abi.json", "w") as f:
    json.dump(abi, f, indent=2)

print(f"Contract deployed at: {tx_receipt.contractAddress}")
print("ABI saved to PharmaChain_abi.json")

with open("contract_address.txt", "w") as f:
    f.write(tx_receipt.contractAddress)
