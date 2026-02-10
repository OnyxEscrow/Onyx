-- Add category column to listings table
ALTER TABLE listings ADD COLUMN category TEXT NOT NULL DEFAULT 'other';
