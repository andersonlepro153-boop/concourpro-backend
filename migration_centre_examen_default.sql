-- ═══════════════════════════════════════════════════════════════════════════
-- MIGRATION (optionnelle, défense en profondeur) : centre_examen tolérant
-- ═══════════════════════════════════════════════════════════════════════════
--
-- La validation applicative (frontend SallesExamen.jsx + backend server.js)
-- exige déjà `centre_examen` à la création d'une salle. Cette migration est
-- un filet de sécurité supplémentaire pour tout futur point d'entrée qui
-- oublierait de le fournir (import SQL direct, script externe...) : au lieu
-- de faire planter l'insertion avec une erreur SQL brute, une valeur par
-- défaut lisible est utilisée.
--
-- ⚠️ Vérifiez d'abord la structure actuelle avec :
--     DESCRIBE salle_examen;
-- Si `centre_examen` a déjà `NULL` dans la colonne "Null" ou un défaut, ne
-- relancez pas cette instruction.

ALTER TABLE `salle_examen`
  MODIFY COLUMN `centre_examen` VARCHAR(255) NOT NULL DEFAULT 'Non renseigné';
