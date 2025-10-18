// --- Imports ---
require('dotenv').config();
console.log("✅ 1. 'dotenv' loaded.");

const { GoogleGenerativeAI } = require('@google/generative-ai');
console.log("✅ 2. Google AI package loaded.");

const axios = require('axios');
console.log("✅ 3. 'axios' package loaded.");

const cheerio = require('cheerio');
console.log("✅ 4. 'cheerio' package loaded.");

const express = require('express');
const cors = require('cors');
console.log("✅ 5. Express and CORS loaded.");

// --- NEW SUPABASE IMPORT ---
const { createClient } = require('@supabase/supabase-js');
console.log("✅ 6. Supabase client loaded.");

// --- AI Setup ---
const apiKey = process.env.GOOGLE_API_KEY;
if (!apiKey) {
  console.error("❌ FATAL ERROR: GOOGLE_API_KEY is not found in your .env file!");
  process.exit(1); 
}
console.log("✅ 7. Google API key found.");

const genAI = new GoogleGenerativeAI(apiKey);
const model = genAI.getGenerativeModel({ model: "gemini-flash-latest" });
console.log("✅ 8. AI Model selected.");

// --- NEW SUPABASE SETUP ---
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error("❌ FATAL ERROR: SUPABASE_URL or SUPABASE_SERVICE_KEY is not found in your .env file!");
  process.exit(1);
}

// Initialize the Supabase admin client
const supabase = createClient(supabaseUrl, supabaseKey);
console.log("✅ 9. Supabase client initialized.");

// --- Server Setup ---
const app = express();
const port = 3000;
app.use(cors());
console.log("✅ 10. Express server configured.");

// --- Scraper Function (No changes) ---
async function getPageContent(url) {
  try {
    const response = await axios.get(url, { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36' } });
    const $ = cheerio.load(response.data);
    const title = $('title').text();
    const description = $('meta[name="description"]').attr('content') || '';
    console.log(`Scraped Title: ${title}`);
    return { title, description };
  } catch (error) {
    console.warn(`Warning: Failed to scrape ${url}. Falling back to URL-only.`);
    return { title: url, description: '' };
  }
}

// --- UPDATED: Database Function ---
// It now accepts an 'apiKey' to find the specific user.
async function getUserRule(apiKey) {
  if (!apiKey) {
    console.error("❌ No API key provided by the extension.");
    return "Block all social media and news."; // A safe default
  }

  console.log("Fetching rule from database for key:", apiKey.substring(0, 5) + "...");
  
  const { data, error } = await supabase
    .from('rules')
    .select('prompt')
    .eq('api_key', apiKey) // <-- Find the rule WHERE api_key matches
    .single();
    
  if (error || !data) {
    console.error("❌ Error fetching rule or key not found:", error?.message);
    // If the key is bad, fall back to a default rule
    return "Block all social media and news.";
  }
  
  console.log("✅ Successfully fetched user-specific rule!");
  return data.prompt;
}

// --- AI Decision Function (Updated) ---
// It now needs the 'apiKey' to pass to the database function.
async function getAIDecision(url, apiKey) {
  
  const { title, description } = await getPageContent(url);
  
  // GET THE SPECIFIC RULE FROM THE DATABASE
  const userRule = await getUserRule(apiKey); 
  
  const prompt = `
    Analyze the following webpage content:
    - Title: "${title}"
    - Description: "${description}"
    - URL: "${url}"
    My user's rule is: "${userRule}"
    Based on the page content and the user's rule, is this website allowed?
    Respond with *only* the word 'ALLOW' or 'BLOCK'.
  `;
  
  try {
    const result = await model.generateContent(prompt);
    const response = await result.response;
    let decision = response.text().trim().toUpperCase();
    if (decision !== 'ALLOW' && decision !== 'BLOCK') {
      console.warn('AI gave an unclear answer. Defaulting to BLOCK.');
      decision = 'BLOCK';
    }
    console.log(`AI decision for ${url} is: ${decision}`);
    return decision;
  } catch (error) {
    console.error('Error contacting AI:', error);
    return 'BLOCK';
  }
}

// --- UPDATED: API Endpoint ---
app.get('/check-url', async (req, res) => {
  const url = req.query.url;
  
  // --- THIS IS THE MODIFIED PART ---

  // 1. We're changing 'x-api-key' to 'authorization'
  const authHeader = req.headers['authorization']; 

  // 2. We're adding this line to split the "Bearer " part off the key
  const apiKey = authHeader ? authHeader.split(' ')[1] : null; 
  
  // --- END OF MODIFIED PART ---
  
  console.log('Received a request for:', url);

  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
    console.log('Ignoring internal Chrome URL.');
    res.json({ decision: 'ALLOW' }); 
    return;
  }
  
  // Pass the apiKey to the decision function
  const decision = await getAIDecision(url, apiKey);
  res.json({ decision: decision });
});

// --- Start the server ---
app.listen(port, () => {
  console.log("✅ 11. SERVER IS LIVE (with User Auth) at http://localhost:3000");
});