-- 043_observed_recovery_target.sql — where a device would actually DIAL to recover.
--
-- ★★★ HOLDING A NAME IS NOT BEING ABLE TO REACH IT (2026-08-20, reported from win-dev-1). The dedicated
-- recovery port was closed on the evidence that every agent REPORTED the recovery name. One of them reported
-- it and would still have dialled the closed port, because sending a name and resolving a destination were
-- two different pieces of code there. The gate read the first and concluded the second.
--
-- ★ AND THIS IS A SEPARATE FILE FOR A REASON. The column was first appended to 042, which this deployment had
-- already applied — so nothing ran, the store dropped every write with "column does not exist", and the
-- posture check went to "no devices reported" for three separate signals. An applied migration is history;
-- new facts need new files.
ALTER TABLE observed_steer_exclusions
  ADD COLUMN IF NOT EXISTS renewal_recovery_target text NOT NULL DEFAULT '';
