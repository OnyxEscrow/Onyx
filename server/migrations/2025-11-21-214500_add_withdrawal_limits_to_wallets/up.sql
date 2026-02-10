ALTER TABLE wallets ADD COLUMN daily_limit_atomic INTEGER DEFAULT 0;
ALTER TABLE wallets ADD COLUMN monthly_limit_atomic INTEGER DEFAULT 0;
ALTER TABLE wallets ADD COLUMN last_withdrawal_date DATE;
ALTER TABLE wallets ADD COLUMN withdrawn_today_atomic INTEGER DEFAULT 0;
