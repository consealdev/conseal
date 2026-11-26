// Shared plumbing for the run.mjs scripts: runs commands the same way on Windows and the Mac,
// and stops at the first one that fails.
//
// Each repo keeps its own copy, so a repo still works when it is cloned on its own. Built-in
// modules only: a run.mjs has to work before `npm install`.

import { spawn, spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import net from 'node:net';

/** A command failed, or could not be started. */
export class RunError extends Error
{
    /**
     * @param {string} message
     * @param {number} code The exit code to finish with.
     * @param {boolean} [shown] True when the failing command already printed why, so only the code is carried.
     */
    constructor(message, code, shown = false)
    {
        super(message);
        this.code = code;
        this.shown = shown;
    }
}

/**
 * Runs one command line through a shell and waits for it, with its output going straight to
 * the terminal.
 *
 * Use it for npm and npx, which are .cmd files on Windows that Node only starts through a
 * shell. That is also why the command is a fixed string written in a run.mjs, never text taken
 * from the command line: use {@link exec} for anything that carries arguments.
 *
 * @param {string} command
 * @param {{ cwd?: string, env?: Record<string, string> }} [options]
 * @throws {RunError} when the command exits non-zero
 */
export function run(command, { cwd, env } = {})
{
    const result = spawnSync(command, {
        cwd,
        env: { ...process.env, ...env },
        shell: true,
        stdio: 'inherit',
    });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new RunError(`${command} exited with code ${result.status}`, result.status ?? 1, true);
}

/**
 * Runs a program with an argument list and no shell, so the arguments are never re-parsed.
 * This works for real executables (node, docker, dotnet, caddy), not for npm or npx.
 *
 * @param {string} file
 * @param {string[]} [args]
 * @param {{ cwd?: string, env?: Record<string, string>, quiet?: boolean }} [options] `quiet` hides the program's output.
 * @throws {RunError} when the program is missing or exits non-zero
 */
export function exec(file, args = [], { cwd, env, quiet = false } = {})
{
    const result = spawnSync(file, args, {
        cwd,
        env: { ...process.env, ...env },
        stdio: quiet ? 'ignore' : 'inherit',
    });
    if (result.error)
    {
        if (result.error.code === 'ENOENT') throw new RunError(`${file} was not found. Is it installed and on your PATH?`, 127);
        throw result.error;
    }
    if (result.status !== 0) throw new RunError(`${[file, ...args].join(' ')} exited with code ${result.status}`, result.status ?? 1, !quiet);
}

/**
 * Runs a program and returns what it printed, or null when it failed or is not installed.
 *
 * @param {string} file
 * @param {string[]} [args]
 * @returns {string | null}
 */
export function capture(file, args = [])
{
    const result = spawnSync(file, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return result.error || result.status !== 0 ? null : result.stdout.trim();
}

/**
 * Whether something is listening on a local port.
 *
 * @param {number} port
 * @param {string} [host]
 * @param {number} [timeout] Milliseconds to wait before calling it closed.
 * @returns {Promise<boolean>}
 */
export function portOpen(port, host = '127.0.0.1', timeout = 1500)
{
    return new Promise(resolve =>
    {
        const socket = net.connect({ port, host });
        const finish = open =>
        {
            socket.destroy();
            resolve(open);
        };
        socket.setTimeout(timeout);
        socket.once('connect', () => finish(true));
        socket.once('timeout', () => finish(false));
        socket.once('error', () => finish(false));
    });
}

/**
 * Opens a URL in the default browser, without waiting for it.
 *
 * @param {string} url
 */
export function openUrl(url)
{
    const [file, args] =
        process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]] :
        process.platform === 'darwin' ? ['open', [url]] :
        ['xdg-open', [url]];
    spawn(file, args, { stdio: 'ignore', detached: true }).unref();
}

/**
 * Runs long-lived commands side by side in this terminal, each line of output prefixed with the
 * command's name. They live and die together: Ctrl+C stops all of them, and so does any one of
 * them ending on its own.
 *
 * Resolves once every command has stopped. Rejects with a {@link RunError} when one of them
 * ended by itself with a non-zero code.
 *
 * @param {{ name: string, command: string, cwd?: string, env?: Record<string, string> }[]} processes
 *        Commands are fixed strings, as for {@link run}.
 * @param {{ signal?: AbortSignal }} [options] Aborting the signal stops the group, as Ctrl+C does.
 * @returns {Promise<void>}
 */
export function group(processes, { signal } = {})
{
    const width = Math.max(...processes.map(p => p.name.length));
    let stopping = false;
    let failure = null;

    const running = processes.map(({ name, command, cwd, env }) =>
    {
        const label = `[${name}]`.padEnd(width + 2) + ' ';
        const child = spawn(command, {
            cwd,
            env: { ...process.env, ...env },
            shell: true,
            stdio: ['ignore', 'pipe', 'pipe'],
            // Its own process group on the Mac, so the whole tree (npm, dotnet, the app) can be signalled at once.
            detached: process.platform !== 'win32',
        });
        prefixLines(child.stdout, process.stdout, label);
        prefixLines(child.stderr, process.stderr, label);

        const finished = new Promise(resolve =>
        {
            child.once('error', error =>
            {
                process.stderr.write(`${label}${error.message}\n`);
                resolve(1);
            });
            // A null code means the child was ended by a signal.
            child.once('close', code => resolve(code ?? 1));
        });
        return { name, label, child, finished, done: false };
    });

    // Only children that have not finished are signalled: once one has, its process id may be
    // reused by an unrelated program.
    const killRunning = force =>
    {
        for (const entry of running)
        {
            if (!entry.done) killTree(entry.child, force);
        }
    };

    // The first Ctrl+C asks the commands to stop; a second one, or five seconds without them
    // stopping, forces it.
    const stop = () =>
    {
        const force = stopping;
        stopping = true;
        killRunning(force);
        if (!force) setTimeout(() => killRunning(true), 5000).unref();
    };

    for (const entry of running)
    {
        entry.finished.then(code =>
        {
            entry.done = true;
            if (stopping) return;
            process.stdout.write(`${entry.label}exited with code ${code}\n`);
            if (code !== 0) failure = { name: entry.name, code };
            stop();
        });
    }

    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    signal?.addEventListener('abort', stop, { once: true });
    if (signal?.aborted) stop();

    return Promise.all(running.map(entry => entry.finished)).then(() =>
    {
        process.off('SIGINT', stop);
        process.off('SIGTERM', stop);
        if (failure) throw new RunError(`${failure.name} exited with code ${failure.code}`, failure.code, true);
    });
}

/**
 * Ends a child and everything it started.
 *
 * @param {import('node:child_process').ChildProcess} child
 * @param {boolean} force
 */
function killTree(child, force)
{
    if (process.platform === 'win32')
    {
        spawnSync('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore' });
        return;
    }
    try
    {
        process.kill(-child.pid, force ? 'SIGKILL' : 'SIGTERM');
    }
    catch
    {
        // The group is already gone.
    }
}

/**
 * @param {import('node:stream').Readable} stream
 * @param {import('node:stream').Writable} out
 * @param {string} label
 */
function prefixLines(stream, out, label)
{
    createInterface({ input: stream }).on('line', line => out.write(`${label}${line}\n`));
}

/**
 * Runs the command named by the arguments. A command can be a function, or a table of
 * sub-commands, with the key `_` for what runs when none is given. A function receives the
 * arguments left over after the command's name.
 *
 * With no arguments it prints the usage text; with an unknown or incomplete command it prints
 * the usage text and exits 1. A failed command sets the exit code rather than printing a stack
 * trace.
 *
 * @param {string} usage
 * @param {Record<string, unknown>} commands
 * @returns {Promise<void>}
 */
export async function main(usage, commands)
{
    const args = process.argv.slice(2);
    const consumed = [];
    const isTable = value => typeof value === 'object' && value !== null;

    let node = commands;
    while (args.length && isTable(node) && Object.hasOwn(node, args[0]))
    {
        consumed.push(args[0]);
        node = node[args.shift()];
    }
    if (isTable(node) && !args.length && Object.hasOwn(node, '_')) node = node._;

    if (typeof node !== 'function')
    {
        if (args.length) console.error(`Unknown command: ${[...consumed, args[0]].join(' ')}\n`);
        else if (consumed.length) console.error(`${consumed.join(' ')} needs a command\n`);
        console.log(usage);
        if (args.length || consumed.length) process.exitCode = 1;
        return;
    }

    try
    {
        await node(args);
    }
    catch (e)
    {
        if (!(e instanceof RunError)) throw e;
        if (!e.shown) console.error(e.message);
        process.exitCode = e.code;
    }
}
