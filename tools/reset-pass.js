/**
 * Reset Passwords Script
 * This script resets all user passwords to 'senha123' (hashed)
 * USE ONLY FOR TESTING/DEVELOPMENT!
 * Run: node reset-passwords.js
 */

require('dotenv').config();
const bcrypt = require('bcryptjs');
const { db } = require('../db');

const DEFAULT_PASSWORD = 'senha123';

console.log('⚠️  WARNING: This will reset ALL user passwords to:', DEFAULT_PASSWORD);
console.log('Press Ctrl+C to cancel, or wait 5 seconds to continue...\n');

setTimeout(async () => {
  console.log('🔐 Resetting passwords...\n');

  const hashedPassword = await bcrypt.hash(DEFAULT_PASSWORD, 12);

  db.run(
    'UPDATE usuarios SET senha = ?, failed_login_attempts = 0, locked_until = NULL',
    [hashedPassword],
    function(err) {
      if (err) {
        console.error('❌ Error resetting passwords:', err);
        process.exit(1);
      }

      console.log(`✅ Reset ${this.changes} user passwords to '${DEFAULT_PASSWORD}'`);
      
      db.all('SELECT id, nome, email FROM usuarios', (err, users) => {
        if (!err && users.length > 0) {
          console.log('\n📋 Users in database:');
          users.forEach(user => {
            console.log(`   - ${user.email} (${user.nome})`);
          });
          console.log(`\nAll users can now login with password: ${DEFAULT_PASSWORD}`);
        }
        process.exit(0);
      });
    }
  );
}, 5000);