require('dotenv').config();
const { Client } = require('pg');
const fs = require('fs');
const path = require('path');

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
    console.error("❌ ERROR: Missing DATABASE_URL in .env");
    console.error("Please add your Supabase connection string to .env:");
    console.error("DATABASE_URL=\"postgres://postgres.[ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres\"");
    process.exit(1);
}

const client = new Client({
    connectionString: databaseUrl,
    ssl: { rejectUnauthorized: false }
});

async function runMigration() {
    try {
        await client.connect();
        console.log("Connected to database.");

        const migrationFile = path.join(__dirname, 'add_active_preset_column.sql');
        console.log("Reading migration file...");
        const sql = fs.readFileSync(migrationFile, 'utf8');

        console.log("Executing SQL migration...");
        await client.query(sql);

        console.log("✅ Migration successful!");
    } catch (err) {
        console.error("❌ Migration Failed:", err);
    } finally {
        await client.end();
    }
}

runMigration();
