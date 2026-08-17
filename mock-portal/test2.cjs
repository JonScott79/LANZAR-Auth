const puppeteer = require('puppeteer');
(async () => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    page.on('console', msg => console.log('PAGE LOG:', msg.text()));
    page.on('pageerror', err => console.log('PAGE ERROR:', err.toString()));
    await page.goto('http://localhost:4000/');
    await new Promise(r => setTimeout(r, 2000));
    const content = await page.content();
    console.log(content.substring(0, 500));
    await browser.close();
})();
