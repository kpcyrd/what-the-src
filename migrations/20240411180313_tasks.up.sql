CREATE TABLE tasks (
    id bigserial PRIMARY KEY,
    key VARCHAR UNIQUE NOT NULL,
    data JSON NOT NULL
);
