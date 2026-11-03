# Relay Payload Builder — receiver=0 Validation Reference

Use this checklist whenever a relay settlement brief asks for a receiver/input validation audit
across the payload-builder set. It is a **cross-reference checklist**, not a final severity report;
complete the finding table during the audit, not in advance.

## Builder inventory and the receiver gate

Check every builder below for:
1. explicit `receiver == address(0)` / `bytes20(0)` / `bytes32(0)` / `receiverNum == 0` guard;
2. implicit guard via address-format validation that rejects zero;
3. downstream receiver propagation into the execution payload / signed hash.

| Builder | Length check | Zero-receiver check | Downstream receiver target | File |
|---|---|---|---|---|
| EthereumVmPayloadBuilder | `params.receiver.length == 20` | **none** | `calls[0].to = receiverAddress`; native `value = amount`; ERC-20 `transfer(receiver, amount)` | `contracts/payload-builders/EthereumVmPayloadBuilder.sol` |
| GatewayVmPayloadBuilder | none on `params.receiver` | **none** | passed into `_buildExecutionPayload(..., params)` | `contracts/payload-builders/GatewayVmPayloadBuilder.sol` |
| GatewayEthereumVmDestinationPayloadBuilder | `params.receiver.length == 20` | **none** | `transfer(address(bytes20(params.receiver)), params.amount)` | `contracts/payload-builders/gateway/GatewayEthereumVmDestinationPayloadBuilder.sol` |
| TronVmPayloadBuilder | `params.receiver.length == 21` | **none** | `Call({to: receiverAddress, value: params.amount, data: ""})` | `contracts/payload-builders/TronVmPayloadBuilder.sol` |
| SolanaVmPayloadBuilder | `receiver.length == 32` | **none** | `fields.recipientPubkey = bytes32(receiver)` | `contracts/payload-builders/SolanaVmPayloadBuilder.sol` |
| HyperliquidVmPayloadBuilder | `params.receiver.length == 20` | **none** | `destination = _addressToString(address(bytes20(params.receiver)))` | `contracts/payload-builders/HyperliquidVmPayloadBuilder.sol` |
| LighterVmPayloadBuilder | none | **none** | `toAccountIndex = _bytesToUint64(params.receiver)` | `contracts/payload-builders/LighterVmPayloadBuilder.sol` |
| XrpVmPayloadBuilder | `params.receiver.length == 20` | **none** | `XrpPaymentRequest.destination = bytes20(params.receiver)` | `contracts/payload-builders/XrpVmPayloadBuilder.sol` |
| BitcoinVmPayloadBuilder | none | **none** | `receiverScript = _protocolAddressToScript(params.receiver)`; first tx output | `contracts/payload-builders/BitcoinVmPayloadBuilder.sol` |
| TonVmPayloadBuilder | `params.receiver.length == 32` | **none** | `TonTransferRequest.receiver = bytes32(params.receiver)` | `contracts/payload-builders/TonVmPayloadBuilder.sol` |
| HederaVmPayloadBuilder | `params.receiver.length == 20` | **yes** via `_entityNum(...)` rejecting `0` and sender-equality | `HederaTransferRequest.receiverNum = receiverNum` | `contracts/payload-builders/HederaVmPayloadBuilder.sol` |
| EmptyPayloadBuilder | N/A — test mock | N/A | N/A | `contracts/mocks/EmptyPayloadBuilder.sol` |

## Downstream depository path

- `RelayGatewayDepository.execute()` executes `Call[]` without a `receiver != address(0)` check in
  `_executeCalls()`. Any builder that omits the zero-receiver guard becomes a burn path if the
  depository is live. If no deployment manifest / `addresses.prod.json` exists for
  `RelayGatewayDepository`, treat this as **UNTESTED deployment dependency**.
- For plain `RelayDepository`, apply the same `calls[i].to == address(0)` review.

## Severity hints, not conclusions

- A zero receiver on a native-value / token-transfer call is usually **HIGH** burn risk.
- A zero receiver on a cross-chain `TransferSpec.destinationRecipient` / execution payload path can
  also be **HIGH**, even when the burn intent targets the depository, because the *execution*
  receiver can still be zero.
- A builder with no amount floor (`amount == 0` not rejected) beside a missing zero-receiver check
  is a stronger finding than either alone.

## Repeated checks

1. Read the full builder file; do not sample the top half.
2. Also read `RelayGatewayDepository.execute()` / `_executeCalls()` and the plain depository
   execute path if in scope.
3. Distinguish **implicit zero rejection** (format validator rejects zero) from **explicit
   `receiver == 0` check**; only the latter is a confirmed guard.
4. Search the deployment manifest (`addresses.prod.json`, `script/Deploy*.s.sol`) for
   `RelayGatewayDepository` before claiming the depository path is live.
