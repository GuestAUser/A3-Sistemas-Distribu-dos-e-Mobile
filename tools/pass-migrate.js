/**
 * Password Migration Script
 * This script will hash all plain text passwords in the database
 * Run this once to fix existing accounts: node migrate-passwords.js
 */

require('dotenv').config();
const bcrypt = require('bcryptjs');
const { db } = require('../db');

console.log('🔐 Starting password migration...\n');

db.all('SELECT id, email, senha FROM usuarios', async (err, users) => {
  if (err) {
    console.error('❌ Error reading users:', err);
    process.exit(1);
  }

  console.log(`Found ${users.length} users to check\n`);

  let migrated = 0;
  let alreadyHashed = 0;
  let errors = 0;

  for (const user of users) {
    try {
      if (user.senha && user.senha.startsWith('$2')) {
        console.log(`✓ ${user.email} - Password already hashed`);
        alreadyHashed++;
        continue;
      }
      console.log(`🔄 ${user.email} - Hashing password...`);
      const hashedPassword = await bcrypt.hash(user.senha || 'senha123', 12);
      await new Promise((resolve, reject) => {
        db.run(
          'UPDATE usuarios SET senha = ? WHERE id = ?',
          [hashedPassword, user.id],
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });

      console.log(`✅ ${user.email} - Password migrated successfully`);
      migrated++;

    } catch (error) {
      console.error(`❌ ${user.email} - Error:`, error.message);
      errors++;
    }
  }

  console.log('\n📊 Migration Summary:');
  console.log(`- Total users: ${users.length}`);
  console.log(`- Migrated: ${migrated}`);
  console.log(`- Already hashed: ${alreadyHashed}`);
  console.log(`- Errors: ${errors}`);

  if (migrated > 0) {
    console.log('\n✅ Password migration completed successfully!');
    console.log('All users can now login with their original passwords.');
  } else if (alreadyHashed === users.length) {
    console.log('\n✅ All passwords are already properly hashed!');
  }

  process.exit(0);
});