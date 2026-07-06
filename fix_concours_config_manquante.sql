-- ============================================================
-- ConcoursPro — Correctif : table manquante concours_config
-- À importer dans phpMyAdmin (onglet SQL) sur la base `concourspro`
-- Peut être exécuté sans risque même si la table existe déjà.
-- ============================================================

USE `concourspro`;

CREATE TABLE IF NOT EXISTS `concours_config` (
  `id`                      VARCHAR(36) NOT NULL DEFAULT (UUID()),
  `concours_id`             VARCHAR(36) NOT NULL,
  `region`                  VARCHAR(100) NOT NULL,
  `filiere`                 VARCHAR(255) NOT NULL,
  `seuil_admission`         DECIMAL(5,2) NOT NULL,
  `quota_places`            INT NOT NULL,
  `quota_liste_attente`     INT DEFAULT 0,
  `priorite_mention`        TINYINT(1) NOT NULL DEFAULT 0,
  `priorite_mentions_ordre` TEXT DEFAULT NULL,
  `notes`                   TEXT,
  `created_date`            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_date`            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by`              VARCHAR(255),
  PRIMARY KEY (`id`),
  KEY `idx_config_concours` (`concours_id`),
  CONSTRAINT `fk_config_concours` FOREIGN KEY (`concours_id`) REFERENCES `concours` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
