const fs = require('fs').promises;
const path = require('path');

// Get the directory where the script is located
const APP_DIR = __dirname;
const DATA_DIR = path.join(APP_DIR, 'data');
const ALL_USERS_DATA_FILE = path.join(DATA_DIR, 'all_users_data.json');

async function migrateData() {
    try {
        console.log('Starting data migration...');
        
        // Read the all_users_data.json file
        console.log(`Reading data from: ${ALL_USERS_DATA_FILE}`);
        const allUsersDataRaw = await fs.readFile(ALL_USERS_DATA_FILE, 'utf8');
        const allUsersData = JSON.parse(allUsersDataRaw);
        
        // Get all UUIDs
        const uuids = Object.keys(allUsersData);
        console.log(`Found ${uuids.length} users to migrate`);
        
        // Create individual files for each user
        for (const uuid of uuids) {
            const userData = allUsersData[uuid];
            const userFilePath = path.join(DATA_DIR, `${uuid}.json`);
            
            console.log(`Migrating data for user ${uuid} to ${userFilePath}`);
            await fs.writeFile(userFilePath, JSON.stringify(userData, null, 2));
        }
        
        // Rename the original file as backup
        const backupFilePath = path.join(DATA_DIR, 'all_users_data.json.bak');
        console.log(`Renaming original file to: ${backupFilePath}`);
        await fs.rename(ALL_USERS_DATA_FILE, backupFilePath);
        
        console.log('Migration completed successfully!');
    } catch (error) {
        console.error('Error during migration:', error);
        process.exit(1);
    }
}

// Run the migration
migrateData();
