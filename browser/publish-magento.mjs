import {readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';

const destination = process.argv[2];
if (!destination) {
    throw new Error('Pass the Magento module directory as the first argument.');
}
for (const [source, relative] of [
    ['dist/runtime.amd.js', 'view/frontend/web/js/runtime.js'],
    ['dist/runtime.less', 'view/frontend/web/css/source/runtime.less']
]) {
    const target = path.join(destination, relative);
    const content = await readFile(new URL(source, import.meta.url));
    if (process.argv.includes('--check')) {
        if (!content.equals(await readFile(target))) {
            throw new Error(`Published Magento asset differs: ${target}`);
        }
    } else {
        await writeFile(target, content);
    }
}
