-- ═══════════════════════════════════════════════════════════════════════════
-- MIGRATION : Ajout de la colonne `notes_locked` dans `candidates`
-- (nécessaire au fonctionnement du verrouillage jury dans SaisieNotes.jsx)
-- ═══════════════════════════════════════════════════════════════════════════
--
-- À exécuter une seule fois sur la base `concourspro`.
-- Vérifie d'abord si la colonne existe déjà, pour éviter une erreur
-- "colonne déjà existante" si vous l'avez déjà ajoutée manuellement.

SELECT COUNT(*) INTO @col_exists
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'candidates'
  AND COLUMN_NAME = 'notes_locked';

SET @sql := IF(@col_exists = 0,
  'ALTER TABLE `candidates` ADD COLUMN `notes_locked` TINYINT(1) NOT NULL DEFAULT 0 AFTER `final_status`',
  'SELECT ''Colonne notes_locked déjà présente, rien à faire.'' AS info'
);

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
