-- Where to send a push (FCM) when an alert fires. Push notifications
-- themselves aren't stored: they're sent and forgotten. Nothing sends them
-- yet.
CREATE TABLE push_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Pushes go to devices of logged-in users; deleting the user removes
    -- their devices.
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- FCM registration token from the app. Unique: a device that
    -- re-registers (or switches user) updates its row instead of getting a
    -- second one, so it isn't pushed twice.
    token TEXT NOT NULL UNIQUE,
    platform TEXT NOT NULL DEFAULT 'android' CHECK (platform IN ('android', 'ios')),
    name TEXT, -- shown to the user, e.g. "Pixel 8"
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')) -- last time the app registered it
);

CREATE INDEX idx_push_devices_user_id ON push_devices (user_id);
