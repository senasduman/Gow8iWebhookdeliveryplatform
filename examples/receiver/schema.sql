CREATE TABLE IF NOT EXISTS receiver_deliveries (
	delivery_id UUID PRIMARY KEY,
	received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS receiver_events (
	delivery_id UUID PRIMARY KEY REFERENCES receiver_deliveries(delivery_id),
	event_type TEXT NOT NULL,
	payload JSONB NOT NULL,
	processed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
