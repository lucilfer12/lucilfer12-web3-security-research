// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { BaseTest } from "./shared/BaseTest.sol";
import { SolvencyGateActive } from "../contracts/shared/Errors.sol";
import { _RAY } from "../contracts/shared/Constants.sol";

contract DifferentialShadowPathTest is BaseTest {
    uint256 internal constant STABLE_AMT = 100e6;
    uint256 internal constant STABLE_AMT18 = 100e18;
    uint256 internal constant RAIN_INK = 800e18;
    uint256 internal constant RAIN_ART = 200e18;

    function setUp() public override {
        super.setUp();
        vm.prank(user);
        vaultEngine.hope(address(collateralAdapter));
    }

    function _setRainPrice(uint256 price) internal {
        rainPriceSource.setPrice(price);
        vm.warp(((vm.getBlockTimestamp() / 1800) + 2) * 1800);
        osm.poke(RAIN_ILK);
        vm.warp(vm.getBlockTimestamp() + 3600);
        osm.poke(RAIN_ILK);
        priceConverter.poke(RAIN_ILK);
    }

    function _openStableVault(address who) internal returns (uint256 vaultId) {
        usdt.mint(who, STABLE_AMT);
        vm.startPrank(who);
        usdt.approve(address(collateralAdapter), STABLE_AMT);
        collateralAdapter.join(USDT_ILK, who, STABLE_AMT);
        vaultId = vaultEngine.open(USDT_ILK, who);
        vaultEngine.frob(vaultId, who, who, int256(STABLE_AMT18), int256(STABLE_AMT18));
        collateralAdapter.exit("USDR", who, STABLE_AMT18);
        vm.stopPrank();
    }
    function _openRainStressVault(address who) internal returns (uint256 vaultId) {
        _setRainPrice(1e18);
        rain.mint(who, RAIN_INK);
        vm.startPrank(who);
        rain.approve(address(collateralAdapter), RAIN_INK);
        collateralAdapter.join(RAIN_ILK, who, RAIN_INK);
        vaultId = vaultEngine.open(RAIN_ILK, who);
        vaultEngine.frob(vaultId, who, who, int256(RAIN_INK), int256(RAIN_ART));
        vm.stopPrank();
    }

    function test_shadowRedemptionMustBeBlockedDuringBreach() public {
        uint256 stableVault = _openStableVault(user);

        // Seed the real reserve and create the same RAIN stress position used by the project's solvency fixture.
        usdt.mint(keeper, 20e6);
        vm.startPrank(keeper);
        usdt.approve(address(psm), 20e6);
        psm.sellStable(USDT_ILK, keeper, 20e6);
        vm.stopPrank();

        _openRainStressVault(user);
        solvencyEngine.checkInvariant();
        assertEq(solvencyEngine.worstCaseLoss(), 60e18, "stress loss");
        assertEq(reserveAccounting.totalReserve(), 20e18, "reserve seed");
        assertTrue(solvencyEngine.isBreached(), "breach active");

        // Official PSM redemption must be blocked.
        vm.startPrank(user);
        usdr.approve(address(psm), STABLE_AMT18);
        vm.expectRevert(SolvencyGateActive.selector);
        psm.buyStable(USDT_ILK, user, STABLE_AMT);
        vm.stopPrank();

        // Restore the internal USDR balance after the reverted PSM attempt.
        vm.startPrank(user);
        usdr.approve(address(collateralAdapter), STABLE_AMT18);
        collateralAdapter.join("USDR", user, STABLE_AMT18);
        vm.stopPrank();

        // The vulnerable implementation succeeds here; the fixed implementation reverts.
        bytes memory data = abi.encodeCall(
            vaultEngine.frob,
            (stableVault, user, user, -int256(STABLE_AMT18), -int256(STABLE_AMT18))
        );

        vm.prank(user);
        (bool shadowSucceeded, ) = address(vaultEngine).call(data);

        uint256 before = usdt.balanceOf(user);
        if (shadowSucceeded) {
            vm.prank(user);
            collateralAdapter.exit(USDT_ILK, user, STABLE_AMT);
        }
        uint256 delta = usdt.balanceOf(user) - before;

        emit log(vm.envString("ATLAS_PROOF_MARKER"));
        emit log(
            string.concat(
                "ATLAS-EFFECT:{\"breach\":true,\"shadow_path\":",
                shadowSucceeded ? "true" : "false",
                ",\"user_asset_delta\":",
                vm.toString(delta),
                "}"
            )
        );

        assertFalse(shadowSucceeded, "shadow redemption must be blocked during breach");
    }
}
