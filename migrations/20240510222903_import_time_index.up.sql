CREATE FUNCTION to_date_char(timestamptz) RETURNS text AS
$$ select to_char($1, 'YYYY-MM-DD'); $$
LANGUAGE sql immutable;

CREATE INDEX artifacts_idx_last_imported ON artifacts (last_imported);
CREATE INDEX artifacts_idx_last_imported_date ON artifacts (to_date_char(last_imported));
