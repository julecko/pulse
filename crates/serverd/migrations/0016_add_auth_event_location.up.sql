-- Where the client of a PAM event was, looked up in the GeoIP database when
-- the event arrived (see geoip.rs). All NULL when rhost isn't a public IP,
-- no database is loaded, or the database doesn't know the IP.
ALTER TABLE auth_events ADD COLUMN country_code TEXT; -- ISO 3166-1 alpha-2
ALTER TABLE auth_events ADD COLUMN country_name TEXT;
ALTER TABLE auth_events ADD COLUMN city TEXT;
