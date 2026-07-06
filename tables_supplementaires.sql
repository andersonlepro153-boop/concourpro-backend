-- ============================================================
-- ConcoursPro — Tables supplémentaires
-- À importer dans phpMyAdmin après concourspro_xampp.sql
-- ============================================================

USE `concourspro`;

-- TABLE : app_users (utilisateurs de l'application)
DROP TABLE IF EXISTS `app_users`;
CREATE TABLE `app_users` (
  `id`            VARCHAR(36)   NOT NULL DEFAULT (UUID()),
  `name`          VARCHAR(255)  NOT NULL,
  `email`         VARCHAR(255)  NOT NULL,
  `password_hash` VARCHAR(255)  NOT NULL,
  `role`          ENUM('super_admin','admin','jury','enseignant','user') NOT NULL DEFAULT 'user',
  `status`        ENUM('actif','suspendu') NOT NULL DEFAULT 'actif',
  `created_date`  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_date`  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by`    VARCHAR(255),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- TABLE : super_admin_config (credentials super administrateur)
DROP TABLE IF EXISTS `super_admin_config`;
CREATE TABLE `super_admin_config` (
  `id`            VARCHAR(36)   NOT NULL DEFAULT (UUID()),
  `name`          VARCHAR(255)  NOT NULL DEFAULT 'Super Admin',
  `email`         VARCHAR(255)  NOT NULL,
  `password_hash` VARCHAR(255)  NOT NULL,
  `created_date`  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_date`  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- TABLE : pointage (présence jour J)
DROP TABLE IF EXISTS `pointage`;
CREATE TABLE `pointage` (
  `id`            VARCHAR(36)   NOT NULL DEFAULT (UUID()),
  `candidate_id`  VARCHAR(36)   NOT NULL,
  `concours_id`   VARCHAR(36),
  `salle_id`      VARCHAR(36),
  `present`       TINYINT(1)    NOT NULL DEFAULT 0,
  `heure_arrivee` TIME,
  `notes`         TEXT,
  `created_date`  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_date`  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by`    VARCHAR(255),
  PRIMARY KEY (`id`),
  KEY `idx_pointage_candidate` (`candidate_id`),
  KEY `idx_pointage_concours`  (`concours_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ─────────────────────────────────────────────────────────────
-- Insertion Super Admin par défaut
-- Email    : cheudjeuanderson@gmail.com
-- Password : cheudjeu2008  (hashé bcrypt, rounds=10)
-- ⚠️  Changez le mot de passe depuis l'interface après le 1er login
-- ─────────────────────────────────────────────────────────────
INSERT INTO `super_admin_config` (`id`, `name`, `email`, `password_hash`)
VALUES (
  UUID(),
  'Anderson',
  'cheudjeuanderson@gmail.com',
  '$2a$10$D9YPI0RrlHFEbLlaE1qCaut8d/nmlw4FuAfYFKWK0dYLwQoQmBpm2'
);
-- ⚠️  Ce hash correspond à 'cheudjeu2008'. Régénérez-le si vous changez le mot de passe.

-- ─────────────────────────────────────────────────────────────
-- Vue utile : liste complète des utilisateurs (users + super_admin)
-- ─────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW `v_all_users` AS
  SELECT id, name, email, role, status, created_date FROM app_users
  UNION ALL
  SELECT id, name, email, 'super_admin' AS role, 'actif' AS status, created_date FROM super_admin_config;

-- ─────────────────────────────────────────────────────────────────────────
-- PATCH : Ajouter filiere_attribuee si la BD existe déjà
-- (Ignorer si la colonne existe déjà)
-- ─────────────────────────────────────────────────────────────────────────
ALTER TABLE `candidates`
  ADD COLUMN IF NOT EXISTS `filiere_attribuee` VARCHAR(255) AFTER `filiere_souhaitee`;

-- ─────────────────────────────────────────────────────────────────────────
-- TABLE : jury_config (mot de passe jury pour saisie des notes)
-- ─────────────────────────────────────────────────────────────────────────
DROP TABLE IF EXISTS `jury_config`;
CREATE TABLE `jury_config` (
  `id`           VARCHAR(36)   NOT NULL DEFAULT (UUID()),
  `pin_hash`     VARCHAR(255)  NOT NULL,
  `updated_date` DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `updated_by`   VARCHAR(255),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- PIN par défaut : cheudjeu2008 (bcrypt hash)
INSERT INTO `jury_config` (`id`, `pin_hash`, `updated_by`)
VALUES (UUID(), '$2a$10$D9YPI0RrlHFEbLlaE1qCaut8d/nmlw4FuAfYFKWK0dYLwQoQmBpm2', 'system');
-- ⚠️ Ce hash correspond à 'cheudjeu2008'. Modifiable depuis Gestion Utilisateurs.

-- ═══════════════════════════════════════════════════════════════════════════
-- CORRECTION URGENTE : Si vous avez déjà importé une ancienne version du SQL
-- et que le mot de passe 'cheudjeu2008' ne fonctionne pas, exécutez ceci :
-- ═══════════════════════════════════════════════════════════════════════════
UPDATE `super_admin_config`
SET `password_hash` = '$2a$10$D9YPI0RrlHFEbLlaE1qCaut8d/nmlw4FuAfYFKWK0dYLwQoQmBpm2'
WHERE `email` = 'cheudjeuanderson@gmail.com';

UPDATE `jury_config`
SET `pin_hash` = '$2a$10$D9YPI0RrlHFEbLlaE1qCaut8d/nmlw4FuAfYFKWK0dYLwQoQmBpm2'
LIMIT 1;
-- Les deux hash ci-dessus correspondent au mot de passe : cheudjeu2008

-- ─────────────────────────────────────────────────────────────────────────
-- PATCH : Ajouter notes_locked dans la table candidates
-- ─────────────────────────────────────────────────────────────────────────
ALTER TABLE `candidates`
  ADD COLUMN IF NOT EXISTS `notes_locked` TINYINT(1) NOT NULL DEFAULT 0
  AFTER `final_status`;
