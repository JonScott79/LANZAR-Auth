const fs = require('fs');
const content = `{
  "framework": "vite",
  "buildCommand": "npm run build",
  "outputDirectory": "dist",
  "rewrites": [
    { "source": "/(.*)", "destination": "/index.html" }
  ]
}
`;
fs.writeFileSync('C:/Projects/LANZAR/auth/vercel.json', content, 'utf8');
