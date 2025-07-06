import { config } from 'dotenv';
config(); // Load environment variables first

import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";

// Import schemas directly to avoid circular dependencies
import * as projectsSchema from "./projects.schema";
import * as backupsSchema from "./backups.schema";
import * as jobsSchema from "./jobs.schema";

// Combine all schemas
const schema = {
  ...projectsSchema,
  ...backupsSchema,
  ...jobsSchema,
};

// Neon PostgreSQL connection
console.log('🔍 Database Environment Variables:', {
  DATABASE_URL: !!process.env.DATABASE_URL,
  PGHOST: process.env.PGHOST,
  PGUSER: process.env.PGUSER,
  PGPASSWORD: !!process.env.PGPASSWORD,
  PGDATABASE: process.env.PGDATABASE
});

const connectionString = process.env.DATABASE_URL || 
  `postgresql://${process.env.PGUSER}:${process.env.PGPASSWORD}@${process.env.PGHOST}/${process.env.PGDATABASE}?sslmode=require`;

console.log('🔗 Final connection string:', connectionString.replace(/:[^:@]*@/, ':***@'));

// Create PostgreSQL connection with error handling
const queryClient = postgres(connectionString, {
  prepare: false,
  ssl: 'require',
  max: 10,
  idle_timeout: 20,
  connect_timeout: 10,
  onnotice: () => {}, // Suppress notices
});

// Create the Drizzle ORM instance with explicit typing
export const db = drizzle(queryClient, { schema });

export type Database = typeof db;

// Test database connection
export async function testDatabaseConnection() {
  try {
    console.log('🔍 Testing database connection...');
    await queryClient`SELECT 1 as test`;
    console.log('✅ Database connection successful');
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    return false;
  }
}

// Initialize database tables if they don't exist
export async function initializeDatabase() {
  try {
    console.log('🔍 Checking if tables exist...');
    
    // Check if projects table exists
    const tablesResult = await queryClient`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      AND table_name IN ('projects', 'backups', 'jobs')
    `;
    
    const existingTables = tablesResult.map(row => row.table_name);
    console.log('📊 Existing tables:', existingTables);
    
    if (existingTables.length === 0) {
      console.log('⚠️ No tables found. Please run database migrations first.');
      console.log('💡 Run: npm run db:push or npm run db:migrate');
      return false;
    }
    
    return true;
  } catch (error) {
    console.error('❌ Failed to initialize database:', error);
    return false;
  }
}