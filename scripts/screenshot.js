const { chromium } = require('playwright');
const path = require('path');

async function takeScreenshots() {
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({
        viewport: { width: 1920, height: 1080 }
    });
    const page = await context.newPage();

    const screenshotDir = path.join(__dirname, '../docs/screenshots');

    console.log('=== Taking NeuroSentry Screenshots ===\n');

    // 1. Grafana Login
    console.log('1. Logging into Grafana...');
    await page.goto('http://localhost:3000/login');
    await page.fill('input[name="user"]', 'admin');
    await page.fill('input[name="password"]', 'admin');
    await page.click('button[type="submit"]');
    await page.waitForTimeout(2000);

    // Skip password change if prompted
    try {
        const skipButton = await page.$('button:has-text("Skip")');
        if (skipButton) await skipButton.click();
    } catch (e) {}

    await page.waitForTimeout(1000);

    // 2. Grafana Dashboard
    console.log('2. Taking Grafana Dashboard screenshot...');
    await page.goto('http://localhost:3000/d/neurosentry/neurosentry-ai-model-security?orgId=1&refresh=5s');
    await page.waitForTimeout(5000); // Wait for panels to load
    await page.screenshot({
        path: path.join(screenshotDir, 'grafana-dashboard.png'),
        fullPage: true
    });
    console.log('   ✅ Saved: grafana-dashboard.png');

    // 3. Prometheus Targets
    console.log('3. Taking Prometheus Targets screenshot...');
    await page.goto('http://localhost:9090/targets');
    await page.waitForTimeout(2000);
    await page.screenshot({
        path: path.join(screenshotDir, 'prometheus-targets.png'),
        fullPage: false
    });
    console.log('   ✅ Saved: prometheus-targets.png');

    // 4. Prometheus Graph - Network Packets
    console.log('4. Taking Prometheus Query screenshot...');
    await page.goto('http://localhost:9090/graph?g0.expr=neurosentry_xdp_packets_total&g0.tab=0&g0.display_mode=lines&g0.show_exemplars=0&g0.range_input=15m');
    await page.waitForTimeout(3000);
    await page.screenshot({
        path: path.join(screenshotDir, 'prometheus-query.png'),
        fullPage: false
    });
    console.log('   ✅ Saved: prometheus-query.png');

    // 5. Metrics endpoint
    console.log('5. Taking Metrics endpoint screenshot...');
    await page.goto('http://localhost:2112/metrics');
    await page.waitForTimeout(1000);
    await page.screenshot({
        path: path.join(screenshotDir, 'metrics-endpoint.png'),
        fullPage: false
    });
    console.log('   ✅ Saved: metrics-endpoint.png');

    await browser.close();
    console.log('\n=== All screenshots saved to docs/screenshots/ ===');
}

takeScreenshots().catch(console.error);
