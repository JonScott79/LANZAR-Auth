const puppeteer = require('puppeteer');
(async () => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    page.on('console', msg => console.log('PAGE LOG:', msg.text()));
    page.on('pageerror', err => console.log('PAGE ERROR:', err.toString()));
    await page.goto('https://auth.lanzar.me/?client_id=tickets&redirect_uri=https%3A%2F%2Ftickets.lanzar.me%2F&state=6eb5d658977e4a58c289b47850efc0287c4a42e1414&code_challenge=J26QvvN3Im4KqgzEdVVLuY8DjQBllrMCvDlL_2TudEo&code_challenge_method=S256', {waitUntil: 'networkidle2'});
    console.log('HTML:', await page.content());
    await browser.close();
})();
