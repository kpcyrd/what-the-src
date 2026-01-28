CREATE TABLE bucket (
    key VARCHAR PRIMARY KEY,
    compressed_size BIGINT NOT NULL,
    uncompressed_size BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX bucket_idx_created_at ON bucket(created_at);
