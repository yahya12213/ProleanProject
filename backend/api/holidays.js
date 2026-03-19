const express = require('express');
const { Pool } = require('pg');
const router = express.Router();

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'prolean',
  password: 'your_password',
  port: 5433,
});

// Get all holidays
router.get('/holidays', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM jours_feries_collectifs ORDER BY date_debut ASC');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching holidays:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Add a new holiday
router.post('/holidays', async (req, res) => {
  const { nom, date_debut, date_fin, type_conge, description, is_recurrent } = req.body;
  try {
    await pool.query(
      'INSERT INTO jours_feries_collectifs (nom, date_debut, date_fin, type_conge, description, is_recurrent) VALUES ($1, $2, $3, $4, $5, $6)',
      [nom, date_debut, date_fin, type_conge, description, is_recurrent]
    );
    res.status(201).json({ message: 'Holiday added successfully' });
  } catch (error) {
    console.error('Error adding holiday:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Update a holiday
router.put('/holidays/:id', async (req, res) => {
  const { id } = req.params;
  const { nom, date_debut, date_fin, type_conge, description, is_recurrent } = req.body;
  try {
    await pool.query(
      'UPDATE jours_feries_collectifs SET nom = $1, date_debut = $2, date_fin = $3, type_conge = $4, description = $5, is_recurrent = $6 WHERE id = $7',
      [nom, date_debut, date_fin, type_conge, description, is_recurrent, id]
    );
    res.json({ message: 'Holiday updated successfully' });
  } catch (error) {
    console.error('Error updating holiday:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Delete a holiday
router.delete('/holidays/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE jours_feries_collectifs SET is_active = false WHERE id = $1', [id]);
    res.json({ message: 'Holiday deactivated successfully' });
  } catch (error) {
    console.error('Error deleting holiday:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

module.exports = router;
