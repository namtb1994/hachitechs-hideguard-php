import {build} from 'esbuild';
import less from 'less';
import {readFile, writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const directory = path.dirname(fileURLToPath(import.meta.url));
const styleText = (await less.render(await readFile(path.join(directory, 'dist/runtime.less'), 'utf8'))).css;
const common = {
    absWorkingDir: directory,
    stdin: {contents: `export {initialize} from './src/runtime.js';\nexport const styleText = ${JSON.stringify(styleText)};`, resolveDir: directory, sourcefile: 'entry.js'},
    bundle: true,
    write: false,
    target: 'es2020',
    legalComments: 'none'
};
// Anonymous AMD module for RequireJS; plain PHP and other platforms use ESM.
const amd = await build({
    ...common, format: 'iife', globalName: 'HideGuardRuntime',
    banner: {js: '/* Generated from browser/src by npm run build. */\ndefine([], function () {'},
    footer: {js: 'return HideGuardRuntime;\n});'}
});
const esm = await build({...common, format: 'esm'});
for (const [name, content] of [
    ['runtime.amd.js', amd.outputFiles[0].text],
    ['runtime.js', esm.outputFiles[0].text],
    ['runtime.styles.json', JSON.stringify(styleText) + '\n']
]) {
    const target = path.join(directory, 'dist', name);
    if (process.argv.includes('--check')) {
        if (await readFile(target, 'utf8') !== content) {
            throw new Error(`Stale runtime asset: ${name}`);
        }
    } else {
        await writeFile(target, content);
    }
}
