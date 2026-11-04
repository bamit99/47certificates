-- Findings remember the scan that last confirmed them, so a finding whose
-- condition no longer holds can be closed when the scan ends "done".
ALTER TABLE findings ADD COLUMN scan_id INTEGER;
