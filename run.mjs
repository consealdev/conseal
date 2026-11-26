// Development commands for the Conseal umbrella. Run with no arguments for the list.

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { main, RunError } from './scripts/run-lib.mjs';

const USAGE = `Usage: node run.mjs <target> <command>

  license check       fail if the copies of COMMERCIAL-LICENSE.md differ

The copies are in conseal-js, conseal-dotnet and the pages repo, so every one of those clones
has to be under repos/.`;

const ROOT = import.meta.dirname;

// One text in three places, and none of them is the source of the others, so there is no `sync`.
const COMMERCIAL_LICENSE_COPIES = [
    'repos/conseal-js/COMMERCIAL-LICENSE.md',
    'repos/conseal-dotnet/COMMERCIAL-LICENSE.md',
    'repos/conseal-pages/www/content/COMMERCIAL-LICENSE.md',
];

function licenseCheck()
{
    const missing = COMMERCIAL_LICENSE_COPIES.filter(name => !existsSync(join(ROOT, name)));
    if (missing.length)
    {
        throw new RunError(`Missing ${missing.join(', ')} (is the clone in repos/?)`, 1);
    }

    // Copies with the same bytes go in one group, the largest group first.
    const groups = [];
    for (const name of COMMERCIAL_LICENSE_COPIES)
    {
        const text = readFileSync(join(ROOT, name));
        const group = groups.find(g => g.text.equals(text));
        if (group) group.names.push(name);
        else groups.push({ text, names: [name] });
    }
    groups.sort((a, b) => b.names.length - a.names.length);

    if (groups.length > 1)
    {
        const lines = groups.map(g => g.names.length > 1
            ? `  the same text in ${g.names.join(' and ')}`
            : `  different: ${g.names[0]}`);
        throw new RunError(`COMMERCIAL-LICENSE.md is not the same in all its copies:\n${lines.join('\n')}`, 1);
    }
    console.log(`COMMERCIAL-LICENSE.md is the same in all ${COMMERCIAL_LICENSE_COPIES.length} copies`);
}

await main(USAGE, {
    license: {
        check: licenseCheck,
    },
});
