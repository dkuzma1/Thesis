/**
 * Integration Test Script for SQL-Enhanced Credential Revocation
 * 
 * This script integrates our SQL module with Schumm's original architecture,
 * and runs comparative performance tests.
 */

const path = require('path');
const { performance } = require('perf_hooks');
const fs = require('fs');

// Import from original CredChain project
// Update these paths based on your actual project structure
const originalSystem = require('../path/to/original/credRevocation');

// Import our integration function
const { integrateWithCredentialRevocation } = require('./integration');

// Output directory for results
const outputDir = path.join(__dirname, 'results');
if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true });
}

// Get the enhanced system
console.log('Integrating SQL module with original system...');
const enhancedSystem = integrateWithCredentialRevocation(originalSystem, {
  dataDir: path.join(__dirname, 'data')
});

// Performance results
const results = {
  timestamp: new Date().toISOString(),
  original: {
    singleVerification: [],
    batchVerification: [],
    singleRevocation: [],
    batchRevocation: []
  },
  enhanced: {
    singleVerification: [],
    batchVerification: [],
    singleRevocation: [],
    batchRevocation: []
  }
};

// Test configuration
const TEST_CONFIG = {
  testRuns: 5,
  credentialCount: 100,
  batchSizes: [10, 50, 100]
};

/**
 * Generate test credentials
 * @param {number} count - Number of credentials to generate
 * @returns {Array} Test credentials
 */
function generateTestCredentials(count) {
  const credentials = [];
  for (let i = 0; i < count; i++) {
    credentials.push({
      id: `test-cred-${i}`,
      epoch: 1 + (i % 5),
      data: `Some test data for credential ${i}`
    });
  }
  return credentials;
}

/**
 * Run the comparative performance tests
 */
async function runTests() {
  console.log('\n=== Starting Performance Comparison Tests ===');
  
  // Generate test data
  const testCredentials = generateTestCredentials(TEST_CONFIG.credentialCount);
  
  // Test 1: Single Verification Performance
  console.log('\n1. Testing Single Verification Performance...');
  for (let i = 0; i < TEST_CONFIG.testRuns; i++) {
    const cred = testCredentials[i];
    
    // Test original system
    console.log(`  Run ${i+1}/${TEST_CONFIG.testRuns} - Original system`);
    const startTimeOriginal = performance.now();
    await originalSystem.verifyCredential(cred.id, cred.epoch);
    const endTimeOriginal = performance.now();
    results.original.singleVerification.push(endTimeOriginal - startTimeOriginal);
    
    // Test enhanced system
    console.log(`  Run ${i+1}/${TEST_CONFIG.testRuns} - Enhanced system`);
    const startTimeEnhanced = performance.now();
    await enhancedSystem.verifyCredential(cred.id, cred.epoch);
    const endTimeEnhanced = performance.now();
    results.enhanced.singleVerification.push(endTimeEnhanced - startTimeEnhanced);
  }
  
  // Test 2: Batch Verification Performance
  console.log('\n2. Testing Batch Verification Performance...');
  for (const batchSize of TEST_CONFIG.batchSizes) {
    console.log(`  Batch size: ${batchSize}`);
    const batchCredentials = testCredentials.slice(0, batchSize);
    
    // Test original system (simulated batch by multiple calls)
    console.log(`  Original system (${batchSize} sequential calls)`);
    const startTimeOriginal = performance.now();
    for (const cred of batchCredentials) {
      await originalSystem.verifyCredential(cred.id, cred.epoch);
    }
    const endTimeOriginal = performance.now();
    results.original.batchVerification.push({
      batchSize,
      executionTime: endTimeOriginal - startTimeOriginal
    });
    
    // Test enhanced system (real batch call)
    console.log(`  Enhanced system (batch call)`);
    const startTimeEnhanced = performance.now();
    await enhancedSystem.batchVerifyCredentials(
      batchCredentials.map(cred => ({ id: cred.id, epoch: cred.epoch }))
    );
    const endTimeEnhanced = performance.now();
    results.enhanced.batchVerification.push({
      batchSize,
      executionTime: endTimeEnhanced - startTimeEnhanced
    });
  }
  
  // Test 3: Single Revocation Performance
  console.log('\n3. Testing Single Revocation Performance...');
  for (let i = 0; i < TEST_CONFIG.testRuns; i++) {
    const cred = testCredentials[TEST_CONFIG.testRuns + i];
    
    // Test original system
    console.log(`  Run ${i+1}/${TEST_CONFIG.testRuns} - Original system`);
    const startTimeOriginal = performance.now();
    await originalSystem.revokeCredential(cred.id, 'test-issuer');
    const endTimeOriginal = performance.now();
    results.original.singleRevocation.push(endTimeOriginal - startTimeOriginal);
    
    // Test enhanced system
    console.log(`  Run ${i+1}/${TEST_CONFIG.testRuns} - Enhanced system`);
    const startTimeEnhanced = performance.now();
    await enhancedSystem.revokeCredential(cred.id, 'test-issuer');
    const endTimeEnhanced = performance.now();
    results.enhanced.singleRevocation.push(endTimeEnhanced - startTimeEnhanced);
  }
  
  // Test 4: Batch Revocation Performance
  console.log('\n4. Testing Batch Revocation Performance...');
  for (const batchSize of TEST_CONFIG.batchSizes) {
    console.log(`  Batch size: ${batchSize}`);
    const batchStart = TEST_CONFIG.testRuns * 2;
    const batchCredentials = testCredentials.slice(batchStart, batchStart + batchSize);
    
    // Test original system (simulated batch by multiple calls)
    console.log(`  Original system (${batchSize} sequential calls)`);
    const startTimeOriginal = performance.now();
    for (const cred of batchCredentials) {
      await originalSystem.revokeCredential(cred.id, 'test-issuer');
    }
    const endTimeOriginal = performance.now();
    results.original.batchRevocation.push({
      batchSize,
      executionTime: endTimeOriginal - startTimeOriginal
    });
    
    // Test enhanced system (real batch call)
    console.log(`  Enhanced system (batch call)`);
    const startTimeEnhanced = performance.now();
    const batchId = enhancedSystem.createRevocationBatch().batchId;
    const batchItems = batchCredentials.map(cred => ({
      credential_id: cred.id,
      epoch_id: cred.epoch,
      issuer_id: 'test-issuer',
      prime_value: cred.id + '-prime' // Simplified prime value for testing
    }));
    enhancedSystem.addToBatch(batchId, batchItems);
    await enhancedSystem.processBatch(batchId);
    const endTimeEnhanced = performance.now();
    results.enhanced.batchRevocation.push({
      batchSize,
      executionTime: endTimeEnhanced - startTimeEnhanced
    });
  }
  
  // Calculate averages and improvements
  calculateResults();
  
  // Save results to file
  const resultsFile = path.join(outputDir, 'performance-comparison.json');
  fs.writeFileSync(resultsFile, JSON.stringify(results, null, 2));
  console.log(`\nResults saved to ${resultsFile}`);
  
  // Generate report
  generateReport();
  
  console.log('\n=== Performance Tests Completed ===');
}

/**
 * Calculate averages and improvements
 */
function calculateResults() {
  // Calculate averages
  results.averages = {
    original: {
      singleVerification: average(results.original.singleVerification),
      singleRevocation: average(results.original.singleRevocation),
      batchVerification: {},
      batchRevocation: {}
    },
    enhanced: {
      singleVerification: average(results.enhanced.singleVerification),
      singleRevocation: average(results.enhanced.singleRevocation),
      batchVerification: {},
      batchRevocation: {}
    }
  };
  
  // Calculate batch verification averages by batch size
  for (const batchSize of TEST_CONFIG.batchSizes) {
    const originalBatch = results.original.batchVerification.find(b => b.batchSize === batchSize);
    const enhancedBatch = results.enhanced.batchVerification.find(b => b.batchSize === batchSize);
    
    if (originalBatch && enhancedBatch) {
      results.averages.original.batchVerification[batchSize] = originalBatch.executionTime;
      results.averages.enhanced.batchVerification[batchSize] = enhancedBatch.executionTime;
    }
  }
  
  // Calculate batch revocation averages by batch size
  for (const batchSize of TEST_CONFIG.batchSizes) {
    const originalBatch = results.original.batchRevocation.find(b => b.batchSize === batchSize);
    const enhancedBatch = results.enhanced.batchRevocation.find(b => b.batchSize === batchSize);
    
    if (originalBatch && enhancedBatch) {
      results.averages.original.batchRevocation[batchSize] = originalBatch.executionTime;
      results.averages.enhanced.batchRevocation[batchSize] = enhancedBatch.executionTime;
    }
  }
  
  // Calculate improvements
  results.improvements = {
    singleVerification: calculateImprovement(
      results.averages.original.singleVerification,
      results.averages.enhanced.singleVerification
    ),
    singleRevocation: calculateImprovement(
      results.averages.original.singleRevocation,
      results.averages.enhanced.singleRevocation
    ),
    batchVerification: {},
    batchRevocation: {}
  };
  
  // Calculate batch improvements
  for (const batchSize of TEST_CONFIG.batchSizes) {
    if (results.averages.original.batchVerification[batchSize] && 
        results.averages.enhanced.batchVerification[batchSize]) {
      results.improvements.batchVerification[batchSize] = calculateImprovement(
        results.averages.original.batchVerification[batchSize],
        results.averages.enhanced.batchVerification[batchSize]
      );
    }
    
    if (results.averages.original.batchRevocation[batchSize] && 
        results.averages.enhanced.batchRevocation[batchSize]) {
      results.improvements.batchRevocation[batchSize] = calculateImprovement(
        results.averages.original.batchRevocation[batchSize],
        results.averages.enhanced.batchRevocation[batchSize]
      );
    }
  }
  
  // Log results
  console.log('\n=== Performance Improvement Summary ===');
  console.log(`Single Verification: ${results.improvements.singleVerification.percentImprovement.toFixed(2)}% improvement`);
  console.log(`Single Revocation: ${results.improvements.singleRevocation.percentImprovement.toFixed(2)}% improvement`);
  
  for (const batchSize of TEST_CONFIG.batchSizes) {
    if (results.improvements.batchVerification[batchSize]) {
      console.log(`Batch Verification (${batchSize}): ${results.improvements.batchVerification[batchSize].percentImprovement.toFixed(2)}% improvement`);
    }
    
    if (results.improvements.batchRevocation[batchSize]) {
      console.log(`Batch Revocation (${batchSize}): ${results.improvements.batchRevocation[batchSize].percentImprovement.toFixed(2)}% improvement`);
    }
  }
}

/**
 * Calculate average of an array
 * @param {Array<number>} arr - Array of numbers
 * @returns {number} Average
 */
function average(arr) {
  if (arr.length === 0) return 0;
  return arr.reduce((sum, val) => sum + val, 0) / arr.length;
}

/**
 * Calculate improvement between original and enhanced values
 * @param {number} original - Original value
 * @param {number} enhanced - Enhanced value
 * @returns {Object} Improvement statistics
 */
function calculateImprovement(original, enhanced) {
  const difference = original - enhanced;
  const percentImprovement = (difference / original) * 100;
  
  return {
    original,
    enhanced,
    difference,
    percentImprovement
  };
}

/**
 * Generate HTML report
 */
function generateReport() {
  const reportFile = path.join(outputDir, 'performance-report.html');
  
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SQL-Enhanced Credential Revocation Performance Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body {
      font-family: Arial, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
    }
    h1, h2, h3 {
      color: #2c3e50;
    }
    .chart-container {
      position: relative;
      height: 400px;
      margin-bottom: 30px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 20px;
    }
    th, td {
      padding: 10px;
      border: 1px solid #ddd;
      text-align: left;
    }
    th {
      background-color: #f2f2f2;
    }
    .improvement {
      color: #27ae60;
      font-weight: bold;
    }
  </style>
</head>
<body>
  <h1>SQL-Enhanced Credential Revocation Performance Report</h1>
  <p>Report generated on: ${new Date().toLocaleString()}</p>
  
  <h2>Single Operation Performance</h2>
  <div class="chart-container">
    <canvas id="singleOperationChart"></canvas>
  </div>
  
  <table>
    <tr>
      <th>Operation</th>
      <th>Original (ms)</th>
      <th>SQL-Enhanced (ms)</th>
      <th>Improvement</th>
    </tr>
    <tr>
      <td>Single Verification</td>
      <td>${results.averages.original.singleVerification.toFixed(2)}</td>
      <td>${results.averages.enhanced.singleVerification.toFixed(2)}</td>
      <td class="improvement">${results.improvements.singleVerification.percentImprovement.toFixed(2)}%</td>
    </tr>
    <tr>
      <td>Single Revocation</td>
      <td>${results.averages.original.singleRevocation.toFixed(2)}</td>
      <td>${results.averages.enhanced.singleRevocation.toFixed(2)}</td>
      <td class="improvement">${results.improvements.singleRevocation.percentImprovement.toFixed(2)}%</td>
    </tr>
  </table>
  
  <h2>Batch Verification Performance</h2>
  <div class="chart-container">
    <canvas id="batchVerificationChart"></canvas>
  </div>
  
  <table>
    <tr>
      <th>Batch Size</th>
      <th>Original (ms)</th>
      <th>SQL-Enhanced (ms)</th>
      <th>Improvement</th>
    </tr>
    ${TEST_CONFIG.batchSizes.map(size => {
      if (!results.improvements.batchVerification[size]) return '';
      return `
    <tr>
      <td>${size}</td>
      <td>${results.averages.original.batchVerification[size].toFixed(2)}</td>
      <td>${results.averages.enhanced.batchVerification[size].toFixed(2)}</td>
      <td class="improvement">${results.improvements.batchVerification[size].percentImprovement.toFixed(2)}%</td>
    </tr>`;
    }).join('')}
  </table>
  
  <h2>Batch Revocation Performance</h2>
  <div class="chart-container">
    <canvas id="batchRevocationChart"></canvas>
  </div>
  
  <table>
    <tr>
      <th>Batch Size</th>
      <th>Original (ms)</th>
      <th>SQL-Enhanced (ms)</th>
      <th>Improvement</th>
    </tr>
    ${TEST_CONFIG.batchSizes.map(size => {
      if (!results.improvements.batchRevocation[size]) return '';
      return `
    <tr>
      <td>${size}</td>
      <td>${results.averages.original.batchRevocation[size].toFixed(2)}</td>
      <td>${results.averages.enhanced.batchRevocation[size].toFixed(2)}</td>
      <td class="improvement">${results.improvements.batchRevocation[size].percentImprovement.toFixed(2)}%</td>
    </tr>`;
    }).join('')}
  </table>
  
  <script>
    // Single Operation Chart
    const singleOpCtx = document.getElementById('singleOperationChart').getContext('2d');
    new Chart(singleOpCtx, {
      type: 'bar',
      data: {
        labels: ['Single Verification', 'Single Revocation'],
        datasets: [
          {
            label: 'Original',
            backgroundColor: 'rgba(54, 162, 235, 0.5)',
            borderColor: 'rgb(54, 162, 235)',
            borderWidth: 1,
            data: [
              ${results.averages.original.singleVerification},
              ${results.averages.original.singleRevocation}
            ]
          },
          {
            label: 'SQL-Enhanced',
            backgroundColor: 'rgba(75, 192, 192, 0.5)',
            borderColor: 'rgb(75, 192, 192)',
            borderWidth: 1,
            data: [
              ${results.averages.enhanced.singleVerification},
              ${results.averages.enhanced.singleRevocation}
            ]
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            title: {
              display: true,
              text: 'Execution Time (ms)'
            }
          }
        },
        plugins: {
          title: {
            display: true,
            text: 'Single Operation Performance Comparison'
          }
        }
      }
    });
    
    // Batch Verification Chart
    const batchVerCtx = document.getElementById('batchVerificationChart').getContext('2d');
    new Chart(batchVerCtx, {
      type: 'bar',
      data: {
        labels: [${TEST_CONFIG.batchSizes.map(size => `'Batch Size ${size}'`).join(', ')}],
        datasets: [
          {
            label: 'Original',
            backgroundColor: 'rgba(54, 162, 235, 0.5)',
            borderColor: 'rgb(54, 162, 235)',
            borderWidth: 1,
            data: [
              ${TEST_CONFIG.batchSizes.map(size => results.averages.original.batchVerification[size] || 0).join(', ')}
            ]
          },
          {
            label: 'SQL-Enhanced',
            backgroundColor: 'rgba(75, 192, 192, 0.5)',
            borderColor: 'rgb(75, 192, 192)',
            borderWidth: 1,
            data: [
              ${TEST_CONFIG.batchSizes.map(size => results.averages.enhanced.batchVerification[size] || 0).join(', ')}
            ]
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            title: {
              display: true,
              text: 'Execution Time (ms)'
            }
          }
        },
        plugins: {
          title: {
            display: true,
            text: 'Batch Verification Performance Comparison'
          }
        }
      }
    });
    
    // Batch Revocation Chart
    const batchRevCtx = document.getElementById('batchRevocationChart').getContext('2d');
    new Chart(batchRevCtx, {
      type: 'bar',
      data: {
        labels: [${TEST_CONFIG.batchSizes.map(size => `'Batch Size ${size}'`).join(', ')}],
        datasets: [
          {
            label: 'Original',
            backgroundColor: 'rgba(54, 162, 235, 0.5)',
            borderColor: 'rgb(54, 162, 235)',
            borderWidth: 1,
            data: [
              ${TEST_CONFIG.batchSizes.map(size => results.averages.original.batchRevocation[size] || 0).join(', ')}
            ]
          },
          {
            label: 'SQL-Enhanced',
            backgroundColor: 'rgba(75, 192, 192, 0.5)',
            borderColor: 'rgb(75, 192, 192)',
            borderWidth: 1,
            data: [
              ${TEST_CONFIG.batchSizes.map(size => results.averages.enhanced.batchRevocation[size] || 0).join(', ')}
            ]
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            title: {
              display: true,
              text: 'Execution Time (ms)'
            }
          }
        },
        plugins: {
          title: {
            display: true,
            text: 'Batch Revocation Performance Comparison'
          }
        }
      }
    });
  </script>
</body>
</html>`;

  fs.writeFileSync(reportFile, html);
  console.log(`HTML report generated at: ${reportFile}`);
}

// Run the tests
runTests().catch(console.error);