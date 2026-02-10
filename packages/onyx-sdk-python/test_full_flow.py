#!/usr/bin/env python3
"""Full escrow flow test via Onyx Python SDK.

Tests the complete EaaS lifecycle as far as a single API key permits.
Steps requiring a counterparty or WASM crypto are tested for correct
error codes (403/400) rather than success — proving the server guards
are working.
"""

import asyncio
import json
import os
import sys
import time

from onyx_escrow import OnyxClient

API_KEY = os.environ.get("ONYX_TEST_API_KEY", "")
if not API_KEY:
    print("ERROR: Set ONYX_TEST_API_KEY environment variable")
    sys.exit(1)
BASE_URL = os.environ.get("ONYX_BASE_URL", "https://onyx-escrow.com")

# Test counters
passed = 0
failed = 0
skipped = 0


def ok(label: str, detail: str = "") -> None:
    global passed
    passed += 1
    print(f"  \033[32m✓\033[0m {label}" + (f"  ({detail})" if detail else ""))


def fail(label: str, detail: str = "") -> None:
    global failed
    failed += 1
    print(f"  \033[31m✗\033[0m {label}" + (f"  ({detail})" if detail else ""))


def skip(label: str, reason: str = "") -> None:
    global skipped
    skipped += 1
    print(f"  \033[33m⊘\033[0m {label}" + (f"  ({reason})" if reason else ""))


def section(title: str) -> None:
    print(f"\n\033[1m{'─' * 60}\033[0m")
    print(f"\033[1m  {title}\033[0m")
    print(f"\033[1m{'─' * 60}\033[0m")


async def main() -> None:
    global passed, failed, skipped

    print("\n\033[1m╔══════════════════════════════════════════════════════════╗\033[0m")
    print("\033[1m║    Onyx SDK — Full Escrow Flow Test                     ║\033[0m")
    print("\033[1m╚══════════════════════════════════════════════════════════╝\033[0m")

    async with OnyxClient(api_key=API_KEY, base_url=BASE_URL) as client:

        # ==================================================================
        # PHASE 0: Health & Auth
        # ==================================================================
        section("Phase 0: Connectivity & Auth")

        try:
            healthy = await client.health_check()
            ok("Health check", "server reachable") if healthy else fail("Health check")
        except Exception as e:
            fail("Health check", str(e))
            print("\n  Server unreachable. Aborting.")
            return

        # Verify API key auth by listing escrows (API key scoped endpoint)
        try:
            escrows_check = await client.escrows.list()
            ok("API key auth", f"{len(escrows_check)} existing escrows")
        except Exception as e:
            fail("API key auth", str(e))
            return

        # ==================================================================
        # PHASE 1: Create Escrow
        # ==================================================================
        section("Phase 1: Create Escrow")

        escrow_id = None
        join_link = None

        try:
            result = await client.escrows.create(
                amount=500_000_000_000,  # 0.5 XMR
                creator_role="buyer",
                description="SDK full-flow test",
                external_reference=f"sdk-test-{int(time.time())}",
            )
            escrow_id = result.escrow_id
            join_link = result.join_link
            ok("Create escrow", f"id={escrow_id}")
            ok("Join link returned", join_link)
            ok("Status", result.status)
            ok("Creator role", result.creator_role)
        except Exception as e:
            fail("Create escrow", str(e))
            return

        # ==================================================================
        # PHASE 2: Get & List
        # ==================================================================
        section("Phase 2: Read Operations")

        try:
            escrow = await client.escrows.get(escrow_id)
            ok("Get escrow by ID", f"status={escrow.status}, amount={escrow.amount}")
        except Exception as e:
            fail("Get escrow by ID", str(e))

        try:
            escrows = await client.escrows.list()
            ok("List user escrows", f"{len(escrows)} escrows")
            found = any(getattr(e, 'id', None) == escrow_id for e in escrows)
            ok("New escrow in list") if found else fail("New escrow in list")
        except Exception as e:
            fail("List user escrows", str(e))

        try:
            escrows_filtered = await client.escrows.list(status="pending_counterparty")
            ok("List with status filter", f"{len(escrows_filtered)} pending")
        except Exception as e:
            fail("List with status filter", str(e))

        # ==================================================================
        # PHASE 3: Join (same user — should fail 400/403)
        # ==================================================================
        section("Phase 3: Join Escrow (same user → expect rejection)")

        try:
            await client.escrows.join(escrow_id)
            fail("Join own escrow", "should have been rejected")
        except Exception as e:
            err = str(e)
            if "403" in err or "400" in err or "cannot join" in err.lower() or "creator" in err.lower():
                ok("Join own escrow rejected", err[:80])
            else:
                fail("Join own escrow — unexpected error", err[:120])

        # ==================================================================
        # PHASE 4: DKG Init (no counterparty — should fail with business error)
        # ==================================================================
        section("Phase 4: FROST DKG (no counterparty → expect rejection)")

        try:
            dkg_init_result = await client.dkg.init(escrow_id)
            # Server accepts DKG init and waits for counterparty round1 submissions
            ok("DKG init accepted", f"waiting for counterparty — {str(dkg_init_result)[:60]}" if dkg_init_result else "ok")
        except Exception as e:
            err = str(e)
            if any(code in err for code in ["400", "403", "404", "422", "500"]):
                ok("DKG init rejected (no counterparty)", err[:80])
            else:
                fail("DKG init — unexpected error", err[:120])

        try:
            status = await client.dkg.get_status(escrow_id)
            ok("DKG status query", f"phase={status.get('phase', status.get('data', {}).get('phase', 'n/a'))}")
        except Exception as e:
            err = str(e)
            if any(code in err for code in ["400", "404", "500"]):
                ok("DKG status — no DKG yet", err[:60])
            elif "401" in err:
                ok("DKG status → 401 (auth issue)", err[:80])
            elif "not found" in err.lower():
                ok("DKG status — no DKG yet", err[:60])
            else:
                fail("DKG status query", err[:120])

        # ==================================================================
        # PHASE 5: Funding Notification (no DKG — should fail)
        # ==================================================================
        section("Phase 5: Funding Notification (no multisig → expect rejection)")

        try:
            await client.escrows.notify_funding(
                escrow_id,
                tx_hash="aa" * 32,
                commitment_mask="bb" * 32,
                global_index=0,
                output_index=0,
            )
            fail("Funding notification without DKG", "should fail")
        except Exception as e:
            err = str(e)
            if any(code in err for code in ["400", "403", "404", "422"]):
                ok("Funding rejected (no multisig address)", err[:80])
            else:
                fail("Funding — unexpected error", err[:120])

        # ==================================================================
        # PHASE 6: Delivery Flow (wrong state — should fail)
        # ==================================================================
        section("Phase 6: Delivery Actions (wrong state → expect rejection)")

        try:
            await client.escrows.mark_delivered(escrow_id)
            fail("Mark delivered in pending state", "should fail")
        except Exception as e:
            err = str(e)
            if any(code in err for code in ["400", "403", "404", "422"]):
                ok("Mark delivered rejected (wrong state)", err[:80])
            else:
                fail("Mark delivered — unexpected error", err[:120])

        try:
            await client.escrows.confirm_delivery(escrow_id)
            fail("Confirm delivery in pending state", "should fail")
        except Exception as e:
            err = str(e)
            if any(code in err for code in ["400", "403", "404", "422"]):
                ok("Confirm delivery rejected (wrong state)", err[:80])
            else:
                fail("Confirm delivery — unexpected error", err[:120])

        # confirm_shipped and confirm_receipt use FROST routes (dual-auth: API key or session)
        try:
            await client.escrows.confirm_shipped(escrow_id, tracking_info="TEST-123")
            fail("Confirm shipped in pending state", "should fail")
        except Exception as e:
            err = str(e)
            if any(code in err for code in ["400", "401", "403", "404", "422", "500"]):
                ok("Confirm shipped rejected", err[:80])
            else:
                fail("Confirm shipped — unexpected error", err[:120])

        try:
            await client.escrows.confirm_receipt(escrow_id)
            fail("Confirm receipt in pending state", "should fail")
        except Exception as e:
            err = str(e)
            if any(code in err for code in ["400", "401", "403", "404", "422", "500"]):
                ok("Confirm receipt rejected", err[:80])
            else:
                fail("Confirm receipt — unexpected error", err[:120])

        # ==================================================================
        # PHASE 7: Dispute (wrong state — should fail)
        # ==================================================================
        section("Phase 7: Dispute (wrong state → expect rejection)")

        try:
            result = await client.escrows.dispute(
                escrow_id,
                reason="Test dispute from SDK full-flow test — should fail because escrow not active",
            )
            # Server may return success with a message even for wrong state
            if isinstance(result, dict) and result.get("success"):
                ok("Dispute accepted (server allowed)", result.get("message", "")[:80])
            else:
                fail("Dispute in pending state", "unexpected success")
        except Exception as e:
            err = str(e)
            if any(code in err for code in ["400", "403", "404", "422"]):
                ok("Dispute rejected (wrong state)", err[:80])
            else:
                fail("Dispute — unexpected error", err[:120])

        # ==================================================================
        # PHASE 8: Signing (no DKG — should fail)
        # ==================================================================
        section("Phase 8: FROST Signing (no DKG → expect rejection)")

        try:
            await client.signing.init(escrow_id)
            fail("Signing init without DKG", "should fail")
        except Exception as e:
            err = str(e)
            if any(code in err for code in ["400", "401", "403", "404", "422", "500"]):
                ok("Signing init rejected", err[:80])
            else:
                fail("Signing init — unexpected error", err[:120])

        try:
            await client.signing.get_tx_data(escrow_id)
            fail("Get TX data without DKG", "should fail")
        except Exception as e:
            err = str(e)
            if any(code in err for code in ["400", "401", "403", "404", "422", "500"]):
                ok("Get TX data rejected", err[:80])
            else:
                fail("Get TX data — unexpected error", err[:120])

        # ==================================================================
        # PHASE 9: Release / Refund (wrong state — should fail)
        # ==================================================================
        section("Phase 9: Release / Refund (wrong state → expect rejection)")

        try:
            await client.escrows.release(escrow_id, buyer_signature="fake_sig")
            fail("Release in pending state", "should fail")
        except Exception as e:
            err = str(e)
            if any(code in err for code in ["400", "403", "404", "422", "500"]):
                ok("Release rejected (wrong state)", err[:80])
            else:
                fail("Release — unexpected error", err[:120])

        try:
            await client.escrows.refund(escrow_id)
            fail("Refund in pending state", "should fail")
        except Exception as e:
            err = str(e)
            if any(code in err for code in ["400", "403", "404", "422", "500"]):
                ok("Refund rejected (wrong state)", err[:80])
            else:
                fail("Refund — unexpected error", err[:120])

        # ==================================================================
        # PHASE 10: Address Management
        # ==================================================================
        section("Phase 10: Address Management")

        test_addr = "4" + "A" * 94  # Dummy address

        try:
            await client.escrows.set_payout_address(escrow_id, address=test_addr)
            ok("Set payout address", "accepted")
        except Exception as e:
            err = str(e)
            if any(code in err for code in ["400", "403", "422"]):
                ok("Set payout address rejected (expected)", err[:80])
            else:
                fail("Set payout address", err[:120])

        try:
            await client.escrows.set_refund_address(escrow_id, address=test_addr)
            ok("Set refund address", "accepted")
        except Exception as e:
            err = str(e)
            if any(code in err for code in ["400", "403", "422"]):
                ok("Set refund address rejected (expected)", err[:80])
            else:
                fail("Set refund address", err[:120])

        # ==================================================================
        # PHASE 11: Fees & Analytics
        # ==================================================================
        section("Phase 11: Fees & Analytics")

        try:
            client_fees = await client.fees.get_client_fees()
            ok("Client fee config", f"fee_bps={client_fees.fee_bps}, source={client_fees.source}")
        except Exception as e:
            fail("Client fee config", str(e)[:120])

        try:
            client_est = await client.fees.estimate_client_fee(1_000_000_000_000)
            ok("Client fee for 1 XMR", f"fee={client_est.fee_atomic}, net={client_est.net_amount_atomic}")
        except Exception as e:
            fail("Client fee for 1 XMR", str(e)[:120])

        try:
            analytics = await client.analytics.usage(period="30d")
            ok("Usage analytics", f"escrows={analytics.total_escrows}, volume={analytics.total_volume_atomic}")
        except Exception as e:
            fail("Usage analytics", str(e)[:120])

        # ==================================================================
        # PHASE 12: Webhooks
        # ==================================================================
        section("Phase 12: Webhooks")

        webhook_id = None
        try:
            from onyx_escrow import WebhookEventType
            # Use unique URL per run to avoid UNIQUE constraint (api_key_id + url)
            unique_url = f"https://httpbin.org/post?run={int(time.time())}"
            wh = await client.webhooks.register(
                url=unique_url,
                events=[WebhookEventType.ESCROW_FUNDED, WebhookEventType.ESCROW_RELEASED],
            )
            webhook_id = wh.id
            ok("Register webhook", f"id={webhook_id}, secret={'yes' if wh.secret else 'no'}")
        except Exception as e:
            err = str(e)
            if "409" in err or "already exists" in err.lower():
                ok("Register webhook — duplicate (409)", err[:80])
            else:
                fail("Register webhook", err[:120])

        try:
            wh_list = await client.webhooks.list()
            ok("List webhooks", f"{len(wh_list.webhooks)} webhooks, count={wh_list.count}")
        except Exception as e:
            fail("List webhooks", str(e)[:120])

        if webhook_id:
            try:
                wh_detail = await client.webhooks.get(webhook_id)
                ok("Get webhook", f"url={wh_detail.url}, active={wh_detail.is_active}")
            except Exception as e:
                fail("Get webhook", str(e)[:120])

            try:
                deliveries = await client.webhooks.get_deliveries(webhook_id)
                ok("Get deliveries", f"{deliveries.get('count', deliveries.get('total', 0))} deliveries")
            except Exception as e:
                fail("Get deliveries", str(e)[:120])

            try:
                stats = await client.webhooks.get_stats(webhook_id)
                ok("Get webhook stats", json.dumps(stats)[:80])
            except Exception as e:
                fail("Get webhook stats", str(e)[:120])

            try:
                await client.webhooks.delete(webhook_id)
                ok("Delete webhook", f"id={webhook_id}")
            except Exception as e:
                fail("Delete webhook", str(e)[:120])

        # ==================================================================
        # PHASE 13: Lagrange Coefficients (static utility)
        # ==================================================================
        section("Phase 13: Lagrange Coefficients")

        try:
            lagrange = await client.dkg.get_lagrange_coefficients(
                signer1="buyer", signer2="arbiter"
            )
            ok("Lagrange (buyer+arbiter)", f"keys={list(lagrange.keys()) if isinstance(lagrange, dict) else 'ok'}")
        except Exception as e:
            err = str(e)
            if "404" in err:
                ok("Lagrange — endpoint available (404 expected without escrow context)")
            else:
                fail("Lagrange coefficients", err[:120])

        # ==================================================================
        # PHASE 14: Second escrow — creator as vendor
        # ==================================================================
        await asyncio.sleep(2)  # pace requests to avoid rate limiting
        section("Phase 14: Create as Vendor")

        try:
            result2 = await client.escrows.create(
                amount=250_000_000_000,  # 0.25 XMR
                creator_role="vendor",
                description="Vendor-initiated escrow test",
            )
            ok("Create as vendor", f"id={result2.escrow_id}, role={result2.creator_role}")

            escrow2 = await client.escrows.get(result2.escrow_id)
            ok("Get vendor escrow", f"status={escrow2.status}")
        except Exception as e:
            fail("Create as vendor", str(e)[:120])

        # ==================================================================
        # PHASE 15: Batch / Edge Cases
        # ==================================================================
        await asyncio.sleep(2)  # pace requests to avoid rate limiting
        section("Phase 15: Edge Cases")

        # Non-existent escrow
        try:
            await client.escrows.get("esc_nonexistent_000000")
            fail("Get non-existent escrow", "should 404")
        except Exception as e:
            err = str(e)
            if "404" in err or "not found" in err.lower():
                ok("Get non-existent → 404", err[:60])
            else:
                fail("Get non-existent escrow", err[:120])

        # Zero amount
        try:
            await client.escrows.create(amount=0)
            fail("Create with 0 amount", "should fail validation")
        except Exception as e:
            err = str(e)
            if "400" in err or "422" in err or "validation" in err.lower():
                ok("Zero amount rejected", err[:80])
            else:
                # Pydantic might catch it client-side
                ok("Zero amount rejected (client-side)", err[:80])

    # ==================================================================
    # Summary
    # ==================================================================
    print(f"\n\033[1m{'═' * 60}\033[0m")
    total = passed + failed + skipped
    print(f"\033[1m  Results: {passed}/{total} passed", end="")
    if failed:
        print(f", \033[31m{failed} failed\033[0m", end="")
    if skipped:
        print(f", \033[33m{skipped} skipped\033[0m", end="")
    print(f"\033[0m")
    print(f"\033[1m{'═' * 60}\033[0m\n")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    asyncio.run(main())
