CREATE INDEX refs_idx_http_filename
ON refs (filename)
WHERE filename LIKE 'http%';
