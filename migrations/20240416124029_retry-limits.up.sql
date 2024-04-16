ALTER TABLE tasks
ADD COLUMN retries SMALLINT NOT NULL DEFAULT 0,
ADD COLUMN error VARCHAR;
CREATE INDEX tasks_idx_retries ON tasks (retries);
