import { test, expect } from '@playwright/test';
const card = (page: any, name: string) => page.getByRole('article', { name: name + ' 응답', exact: true });
for (const width of [1440, 768, 390]) {
    test(`Demo 질문, 실패/timeout, retry, 반응형 ${width}`, async ({ page }) => {
        const errors: string[] = [];
        page.on('pageerror', e => errors.push(e.message));
        await page.setViewportSize({ width, height: 1000 });
        await page.goto('/');
        await expect(page.getByText('지금은 체험 모드예요.', { exact: false })).toBeVisible();
        await expect(page.getByRole('button', { name: '답변 비교하기' })).toBeDisabled();
        const boxes = await page.locator('.model-card').evaluateAll(nodes => nodes.map(n => ({ x: n.getBoundingClientRect().x, y: n.getBoundingClientRect().y })));
        expect(boxes.length).toBe(3);
        if (width === 1440)
            expect(boxes[0].y).toBe(boxes[2].y);
        if (width === 768) {
            expect(boxes[0].y).toBe(boxes[1].y);
            expect(boxes[2].y).toBeGreaterThan(boxes[0].y);
        }
        if (width === 390)
            expect(boxes[1].y).toBeGreaterThan(boxes[0].y);
        await page.screenshot({ path: test.info().outputPath(`demo-empty-${width}.png`), fullPage: true });
        await page.getByLabel('어떤 점이 궁금하세요?').fill('개인 프로젝트를 시작할 때 무엇부터 하면 좋을까요?');
        await page.getByRole('button', { name: '답변 비교하기' }).click();
        await expect(page.getByRole('button', { name: '답변을 모으고 있어요' })).toBeDisabled();
        await expect(card(page, 'GPT').locator('.status')).toHaveText('완료');
        await expect(card(page, 'Gemini').locator('.status')).toHaveText('실패');
        await expect(card(page, 'Claude').locator('.status')).toHaveText('시간 초과');
        const gpt = await card(page, 'GPT').textContent();
        await expect(card(page, 'GPT').getByRole('button', { name: '다시 시도' })).toHaveCount(0);
        await card(page, 'Gemini').getByRole('button', { name: '다시 시도' }).click();
        await expect(card(page, 'Gemini').locator('.status')).toHaveText('완료');
        await card(page, 'Claude').getByRole('button', { name: '다시 시도' }).click();
        await expect(card(page, 'Claude').locator('.status')).toHaveText('완료');
        expect(await card(page, 'GPT').textContent()).toBe(gpt);
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
        expect(errors).toEqual([]);
        await page.screenshot({ path: test.info().outputPath(`demo-complete-${width}.png`), fullPage: true });
    });
}
test('키보드만으로 입력, 선택, Ask, Retry', async ({ page }) => {
    await page.goto('/');
    await page.keyboard.press('Tab');
    await expect(page.getByLabel('어떤 점이 궁금하세요?')).toBeFocused();
    await page.keyboard.type('Keyboard flow');
    await page.keyboard.press('Tab');
    await expect(page.getByRole('checkbox', { name: 'GPT', exact: true })).toBeFocused();
    await page.keyboard.press('Space');
    await page.keyboard.press('Space');
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: '답변 비교하기' })).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(card(page, 'Claude').locator('.status')).toHaveText('시간 초과');
    // Start from the document and navigate through enabled controls to retry.
    await page.keyboard.press('Tab');
    for (let i = 0; i < 12; i++) {
        if (await card(page, 'Gemini').getByRole('button', { name: '다시 시도' }).evaluate((el: Element) => el === document.activeElement))
            break;
        await page.keyboard.press('Tab');
    }
    await expect(card(page, 'Gemini').getByRole('button', { name: '다시 시도' })).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(card(page, 'Gemini').locator('.status')).toHaveText('완료');
});
test('위험 HTML과 긴 답변은 텍스트로 표시', async ({ page }) => {
    await page.goto('/');
    const payload = '<script>window.pwned=true</script> javascript:alert(1)\n' + '긴 코드와 응답 '.repeat(700);
    await page.route('**/api/runs', async (route) => {
        await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ run_id: 'safe-fixture', prompt: '안전 표시', mode: 'demo', models: { gpt: { attempt_id: 1, status: 'complete', response: payload, queued_at: 1, started_at: 1, finished_at: 2, error: null } } }) });
    });
    await page.getByLabel('어떤 점이 궁금하세요?').fill('안전 표시');
    await page.getByRole('button', { name: '답변 비교하기' }).click();
    await expect(card(page, 'GPT').locator('.response')).toContainText('<script>');
    expect(await page.evaluate(() => (window as any).pwned)).toBeUndefined();
    expect(await card(page, 'GPT').locator('script,a').count()).toBe(0);
    for (const width of [1440, 768, 390]) {
        await page.setViewportSize({ width, height: 900 });
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
        expect(await card(page, 'GPT').locator('.answer').evaluate((el: Element) => el.scrollHeight > el.clientHeight)).toBe(true);
    }
});
