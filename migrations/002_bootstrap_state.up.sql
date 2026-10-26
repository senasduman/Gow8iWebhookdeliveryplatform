DO $$
BEGIN
	IF EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_name = 'webhook_endpoints' AND column_name = 'secret'
	) THEN
		ALTER TABLE webhook_endpoints RENAME COLUMN secret TO secret_legacy;
		ALTER TABLE webhook_endpoints ADD COLUMN secret_ciphertext BYTEA;
	END IF;
END $$;

CREATE TABLE bootstrap_state (
	id SMALLINT PRIMARY KEY CHECK (id = 1),
	consumed BOOLEAN NOT NULL DEFAULT false,
	consumed_at TIMESTAMPTZ
);
INSERT INTO bootstrap_state (id, consumed)
SELECT 1, EXISTS (SELECT 1 FROM organizations);
