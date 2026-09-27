-- Releases of the Android app (`PUT /app-releases/{version_code}`,
-- `pulse-server-cli app upload`), which the app downloads to update itself.
-- The APK itself is a file in `[app_releases] dir`, named after its
-- version code.
CREATE TABLE app_releases (
    version_code INTEGER PRIMARY KEY CHECK (version_code BETWEEN 1 AND 2100000000),
    version_name TEXT NOT NULL,
    notes TEXT,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL, -- lowercase hex
    uploaded_by TEXT, -- username
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
