SET search_path TO app, extensions, public;

CREATE OR REPLACE FUNCTION protect_loyalty_history() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'published loyalty history is immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_loyalty_point_ledger_immutable
BEFORE UPDATE OR DELETE ON loyalty_point_ledger
FOR EACH ROW EXECUTE FUNCTION protect_loyalty_history();

CREATE OR REPLACE FUNCTION protect_published_loyalty_tier() RETURNS trigger AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM loyalty_program_versions v
    WHERE v.id = OLD.program_version_id AND v.status <> 'PENDING_APPROVAL'
  ) THEN
    RAISE EXCEPTION 'published loyalty tiers are immutable';
  END IF;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_loyalty_tier_band_immutable
BEFORE UPDATE OR DELETE ON loyalty_tier_bands
FOR EACH ROW EXECUTE FUNCTION protect_published_loyalty_tier();

CREATE OR REPLACE FUNCTION validate_loyalty_program_version() RETURNS trigger AS $$
BEGIN
  IF NEW.status IN ('SCHEDULED', 'ACTIVE') THEN
    IF NOT EXISTS (
      SELECT 1 FROM loyalty_tier_bands b
      WHERE b.program_version_id = NEW.id AND b.minimum_points = 0
    ) THEN
      RAISE EXCEPTION 'loyalty program must have a zero-point tier';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER trg_validate_loyalty_program_version
AFTER INSERT OR UPDATE OF status ON loyalty_program_versions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_loyalty_program_version();
