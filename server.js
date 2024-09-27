const express = require('express');
const app = express();
const port = 8888;

// Serve static files from the current directory (where index.html and app.js are located)
app.use(express.static(__dirname));

// Bind to 0.0.0.0 to make the app accessible from outside the host (e.g., Docker)
app.listen(port, '0.0.0.0', () => {
    console.log(`Server is running at http://localhost:${port}`);
});
