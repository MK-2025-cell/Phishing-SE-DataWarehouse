-- ============================================================
-- Step 6c: Scalability Test
-- Duplicates fact_incident data to 5x and 10x its real size,
-- re-measures the same OLAP queries, then ROLLS BACK everything
-- so your real 6,726-row dataset is untouched afterward.
-- ============================================================

BEGIN;

-- Baseline size check
SELECT count(*) AS baseline_row_count FROM fact_incident;

\echo '--- BASELINE (1x, ~6,726 rows) ---'
EXPLAIN ANALYZE
SELECT t.year, t.month, at.attack_category, sv.severity_level, count(*)
FROM fact_incident f
JOIN dim_time t ON f.time_key = t.time_key
JOIN dim_attack_type at ON f.attack_type_key = at.attack_type_key
JOIN dim_severity sv ON f.severity_key = sv.severity_key
GROUP BY ROLLUP (t.year, t.month, at.attack_category, sv.severity_level);

-- --- Grow to ~5x by inserting 4 more duplicate copies ---
INSERT INTO fact_incident
  (time_key, attack_type_key, source_key, target_key, severity_key,
   detection_method_key, incident_id, data_source, label,
   detection_score, response_time_sec, financial_loss_est, is_confirmed, url_or_reference)
SELECT time_key, attack_type_key, source_key, target_key, severity_key,
       detection_method_key, incident_id || '_dup' || gs.i, data_source, label,
       detection_score, response_time_sec, financial_loss_est, is_confirmed, url_or_reference
FROM fact_incident, generate_series(1,4) AS gs(i);

SELECT count(*) AS row_count_after_5x FROM fact_incident;

\echo '--- 5x SCALE (~33,630 rows) ---'
EXPLAIN ANALYZE
SELECT t.year, t.month, at.attack_category, sv.severity_level, count(*)
FROM fact_incident f
JOIN dim_time t ON f.time_key = t.time_key
JOIN dim_attack_type at ON f.attack_type_key = at.attack_type_key
JOIN dim_severity sv ON f.severity_key = sv.severity_key
GROUP BY ROLLUP (t.year, t.month, at.attack_category, sv.severity_level);

-- --- Grow further to ~10x total ---
INSERT INTO fact_incident
  (time_key, attack_type_key, source_key, target_key, severity_key,
   detection_method_key, incident_id, data_source, label,
   detection_score, response_time_sec, financial_loss_est, is_confirmed, url_or_reference)
SELECT time_key, attack_type_key, source_key, target_key, severity_key,
       detection_method_key, incident_id || '_dup2_' || gs.i, data_source, label,
       detection_score, response_time_sec, financial_loss_est, is_confirmed, url_or_reference
FROM fact_incident, generate_series(1,1) AS gs(i);

SELECT count(*) AS row_count_after_10x FROM fact_incident;

\echo '--- 10x SCALE (~67,260 rows) ---'
EXPLAIN ANALYZE
SELECT t.year, t.month, at.attack_category, sv.severity_level, count(*)
FROM fact_incident f
JOIN dim_time t ON f.time_key = t.time_key
JOIN dim_attack_type at ON f.attack_type_key = at.attack_type_key
JOIN dim_severity sv ON f.severity_key = sv.severity_key
GROUP BY ROLLUP (t.year, t.month, at.attack_category, sv.severity_level);

-- Undo everything -- real data is restored to exactly 6,726 rows
ROLLBACK;

SELECT count(*) AS confirmed_restored_count FROM fact_incident;
