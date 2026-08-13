import test from 'ava';
const packageName = '@stefanobalocco/scryptserver';
const rootModule = await import(packageName);
test('package root: default export equals the named ScryptClient export', (t) => {
    t.is(rootModule.default, rootModule.ScryptClient);
});
test('package root: has no ScryptServer export', (t) => {
    t.falsy(rootModule.ScryptServer);
});
test('package root: has no DefaultConfig export', (t) => {
    t.falsy(rootModule.DefaultConfig);
});
test('package: ScryptServer subpath is not exported', async (t) => {
    const subpath = packageName + '/ScryptServer';
    await t.throwsAsync(async () => { await import(subpath); }, { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });
});
test('package: DefaultConfig subpath is not exported', async (t) => {
    const subpath = packageName + '/DefaultConfig';
    await t.throwsAsync(async () => { await import(subpath); }, { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });
});
