const puppeteer = require('puppeteer');
(async () => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    page.on('console', msg => console.log('PAGE LOG:', msg.text()));
    page.on('pageerror', err => console.log('PAGE ERROR:', err.toString()));
    await page.goto('http://localhost:8000/');
    await new Promise(r => setTimeout(r, 2000));
    console.log('STATUS:', await page.$eval('#status', el => el.innerText));
    console.log('ERROR LOG:', await page.$eval('#errorLog', el => el.innerText));
    await browser.close();
})();
