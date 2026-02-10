-- Add columns for partial key images in 2-of-3 multisig CLSAG signing
-- Each participant submits their partial key image: pKI_i = x_i * Hp(P_multisig)
-- The server aggregates them: KI_total = pKI_buyer + pKI_vendor (Edwards point addition)

ALTER TABLE escrows ADD COLUMN buyer_partial_key_image TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN vendor_partial_key_image TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN arbiter_partial_key_image TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN aggregated_key_image TEXT DEFAULT NULL;
