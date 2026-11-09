const fs = require('fs');
const content = `[build]
  command = "npm run build"
  publish = "dist"

[[redirects]]
  from = "/*"
  to = "/index.html"
  status = 200
`;
fs.writeFileSync('C:/Projects/LANZAR/auth/netlify.toml', content, 'utf8');
