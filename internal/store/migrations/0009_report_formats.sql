-- The report formats a reader can ask for. The PDF and the Markdown are
-- generated alongside the HTML, the CSV and the JSON.
ALTER TABLE reports ADD COLUMN md_path TEXT;
ALTER TABLE reports ADD COLUMN pdf_path TEXT;

-- A report covers one domain.
ALTER TABLE reports ADD COLUMN domain_id INTEGER REFERENCES domains(id);
