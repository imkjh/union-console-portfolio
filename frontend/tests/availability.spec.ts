import { test, expect } from '@playwright/test';

// API fixtures exercise availability UI. These are NOT live-provider evidence.
for (const width of [1440, 390]) {
    test(`합성 API: GPT만 준비된 화면 ${width}`, async ({ page }) => {
        const errors: string[] = [];
        page.on('pageerror', error => errors.push(error.message));
        await page.setViewportSize({ width, height: 1000 });
        await page.route('**/api/health', route => route.fulfill({ json: {
            status: 'ok', mode: 'live', csrf_token: 'synthetic-fixture', live_ready: false,
        } }));
        await page.route('**/api/models', route => route.fulfill({ json:
            ['GPT', 'Gemini', 'Claude'].map(name => ({ id: name.toLowerCase(), name,
                model_id: 'synthetic-model', provider: '합성 API 시험',
                available: name === 'GPT', mode: 'live' })),
        }));
        const requests: unknown[] = [];
        await page.route('**/api/runs', route => {
            requests.push(route.request().postDataJSON());
            return route.fulfill({ status: 201, json: { run_id: 'synthetic-run', mode: 'live',
                prompt: '합성 시험 질문', models: { gpt: { attempt_id: 1, status: 'complete',
                    response: '합성 응답입니다. 실제 모델을 호출하지 않았습니다.', error: null,
                    queued_at: 1, started_at: 1, finished_at: 2 } } } });
        });
        await page.goto('/');
        await expect(page.getByText('일부 모델 연결됨')).toBeVisible();
        await expect(page.getByRole('checkbox', { name: 'GPT', exact: true })).toBeChecked();
        for (const name of ['Gemini', 'Claude']) {
            const checkbox = page.getByRole('checkbox', { name, exact: true });
            await expect(checkbox).not.toBeChecked();
            await expect(checkbox).toBeDisabled();
            await expect(page.getByRole('article', { name: name + ' 응답', exact: true })
                .getByText('연결을 준비하고 있어요')).toBeVisible();
        }
        await page.getByLabel('어떤 점이 궁금하세요?').fill('합성 시험 질문');
        await page.getByRole('button', { name: '답변 비교하기' }).click();
        await expect(page.getByText('합성 응답입니다.', { exact: false })).toBeVisible();
        await expect(page.getByRole('button', { name: '답변 비교하기' })).toBeEnabled();
        expect(requests).toEqual([{ prompt: '합성 시험 질문', models: ['gpt'] }]);
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
        expect(errors).toEqual([]);
        // Explicit watermark prevents this artifact being mistaken for live proof.
        await page.evaluate(() => {
            const note = document.createElement('p');
            note.textContent = '합성 API UI 검증 · 실제 CLI/모델 호출 없음';
            note.style.cssText = 'background:#fff0c2;color:#412e00;padding:16px;text-align:center;font-weight:bold';
            document.body.prepend(note);
        });
        await page.screenshot({ path: test.info().outputPath(`synthetic-partial-${width}.png`), fullPage: true, animations: 'disabled' });
    });
}

test('미등록 Live 모델은 모두 선택 해제하고 질문 전송 차단', async ({ page }) => {
    await page.route('**/api/health', route => route.fulfill({ json: {
        status: 'ok', mode: 'live', csrf_token: 'synthetic-fixture', live_ready: false,
    } }));
    await page.route('**/api/models', route => route.fulfill({ json:
        ['GPT', 'Gemini', 'Claude'].map(name => ({ id: name.toLowerCase(), name,
            model_id: 'synthetic-model', provider: '합성 API 시험', available: false, mode: 'live' })),
    }));
    await page.goto('/');
    await expect(page.getByText('사용 가능한 모델이 아직 없어요.')).toBeVisible();
    await page.getByLabel('어떤 점이 궁금하세요?').fill('실행하면 안 되는 질문');
    await expect(page.getByRole('button', { name: '답변 비교하기' })).toBeDisabled();
    for (const checkbox of await page.getByRole('checkbox').all()) {
        await expect(checkbox).not.toBeChecked();
        await expect(checkbox).toBeDisabled();
    }
});

for (const code of ['network_unavailable', 'auth_required', 'rate_limited', 'timeout']) {
    test(`합성 GPT 오류와 수동 재시도: ${code}`, async ({ page }) => {
        const issues: string[] = [];
        page.on('pageerror', e => issues.push(e.message));
        page.on('console', e => { if (e.type() === 'error') issues.push(e.text()); });
        await page.setViewportSize({ width: 390, height: 1000 });
        await page.route('**/api/health', route => route.fulfill({ json: {
            mode: 'live', csrf_token: 'synthetic-only', live_ready: false,
        } }));
        await page.route('**/api/models', route => route.fulfill({ json:
            ['GPT', 'Gemini', 'Claude'].map(name => ({ id: name.toLowerCase(), name,
                model_id: 'synthetic-model', provider: '합성 오류 시험',
                mode: 'live', available: name === 'GPT' })),
        }));
        let submissions = 0, retries = 0;
        const run = { run_id: 'synthetic-fault', prompt: '합성 오류 검사', mode: 'live', models: {
            gpt: { attempt_id: 1, status: code === 'timeout' ? 'timeout' : 'failed', response: null as string | null,
                error: code as string | null, queued_at: 1, started_at: 1, finished_at: 2 },
        } };
        await page.route('**/api/runs', route => {
            submissions++;
            expect(route.request().postDataJSON()).toEqual({ prompt: run.prompt, models: ['gpt'] });
            return route.fulfill({ status: 201, json: run });
        });
        await page.route('**/api/runs/synthetic-fault/models/gpt/retry', route => {
            retries++;
            expect(route.request().postDataJSON()).toEqual({});
            run.models.gpt = { ...run.models.gpt, attempt_id: 2, status: 'complete', error: null,
                response: '합성 재시도 성공 · 실제 모델 호출 없음' };
            return route.fulfill({ json: run });
        });
        await page.goto('/');
        await expect(page.getByText('기존 구독의 사용량이 소모돼요.', { exact: false })).toBeVisible();
        await page.getByLabel('어떤 점이 궁금하세요?').fill(run.prompt);
        await page.getByRole('button', { name: '답변 비교하기' }).click();
        const card = page.getByRole('article', { name: 'GPT 응답', exact: true });
        await expect(card.locator('.status')).toHaveText(code === 'timeout' ? '시간 초과' : '실패');
        await page.waitForTimeout(600);
        expect(retries).toBe(0); // No automatic subscription-consuming retry.
        await card.getByRole('button', { name: '다시 시도' }).click();
        await expect(card.locator('.status')).toHaveText('완료');
        await expect(card.getByText('시도 2')).toBeVisible();
        await expect(page.getByRole('button', { name: '다시 시도' })).toHaveCount(0);
        expect({ submissions, retries }).toEqual({ submissions: 1, retries: 1 });
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        expect(issues).toEqual([]);
        if (code === 'network_unavailable') {
            await page.evaluate(() => {
                const label = document.createElement('p');
                label.textContent = '합성 GPT 오류/재시도 UI 검증 · 실제 모델 호출 없음';
                label.style.cssText = 'padding:16px;background:#fff0c2;color:#412e00;text-align:center';
                document.body.prepend(label);
            });
            await page.screenshot({ path: test.info().outputPath('synthetic-gpt-retry-390.png'), fullPage: true });
        }
    });
}

test('서버가 실행 결과를 잃으면 polling을 멈추고 새 질문 허용', async ({ page }) => {
    let polls = 0;
    await page.route('**/api/runs', route => route.fulfill({ status: 201, json: {
        run_id: 'lost-run', prompt: '유실 검사', mode: 'demo', models: { gpt: {
            attempt_id: 1, status: 'running', response: null, error: null, queued_at: 1, started_at: 1, finished_at: null,
        } },
    } }));
    await page.route('**/api/runs/lost-run', route => {
        polls++;
        return route.fulfill({ status: 404, json: { error: 'run_missing' } });
    });
    await page.goto('/');
    await page.getByLabel('어떤 점이 궁금하세요?').fill('유실 검사');
    await page.getByRole('button', { name: '답변 비교하기' }).click();
    await expect(page.getByRole('alert')).toContainText('결과가 만료되었거나');
    await expect(page.getByLabel('어떤 점이 궁금하세요?')).toBeEnabled();
    await expect(page.getByLabel('어떤 점이 궁금하세요?')).toHaveValue('유실 검사');
    await expect(page.getByRole('button', { name: '답변 비교하기' })).toBeEnabled();
    await page.waitForTimeout(1100);
    expect(polls).toBe(1);
});
