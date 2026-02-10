-- Add external_reference and description columns to escrows
-- external_reference: Replaces order_id for EaaS (optional external tracking ID)
-- description: Escrow purpose/description for EaaS clients

ALTER TABLE escrows ADD COLUMN external_reference TEXT;
ALTER TABLE escrows ADD COLUMN description TEXT;

-- Copy existing order_id values to external_reference for backward compatibility
UPDATE escrows SET external_reference = order_id WHERE external_reference IS NULL;
