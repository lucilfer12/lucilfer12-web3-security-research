// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { BaseTest } from "./shared/BaseTest.sol";
import { _RAY } from "../contracts/shared/Constants.sol";

contract AtlasBaseline is BaseTest {
    function test_atlas_baseline_is_healthy() public {
        assertEq(vaultEngine.live(), 1, "vault engine live");
        assertEq(solvencyEngine.breached(), false, "solvency baseline not breached");
        assertEq(reserveAccounting.totalReserve(), 0, "baseline reserve");
        (, , uint256 rate, , , , , ) = vaultEngine.ilks(USDT_ILK);
        assertEq(rate, _RAY, "stable rate at par");
        assertEq(vaultEngine.noFee(USDT_ILK), true, "stable ilk fee exempt");
    }
}
