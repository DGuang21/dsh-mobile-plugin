import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../plugins/dsh-bridge/panel-ui');

interface QrCode {
  addData(value: string, mode?: string): void;
  make(): void;
  getModuleCount(): number;
  isDark(row: number, column: number): boolean;
}

describe('shipped management panel assets', () => {
  it('leaves the bootstrap placeholder executable rather than inside an HTML comment', () => {
    const html = readFileSync(join(root, 'index.html'), 'utf8');
    const placeholder = '%%DSH_MOBILE_BRIDGE_BOOTSTRAP%%';
    const position = html.indexOf(placeholder);
    expect(position).toBeGreaterThan(-1);

    const commentOpen = html.lastIndexOf('<!--', position);
    const commentClose = html.lastIndexOf('-->', position);
    expect(commentOpen).toBeLessThanOrEqual(commentClose);
  });

  it('ships every static asset the HTML loads', () => {
    const html = readFileSync(join(root, 'index.html'), 'utf8');
    const assets = [...html.matchAll(/(?:href|src)="([^"]+)"/g)]
      .map((match) => match[1])
      .filter((asset): asset is string => asset !== undefined && asset !== './');
    expect(assets).toEqual(['panel.css', 'vendor/qrcode.js', 'panel.js']);
    for (const asset of assets) expect(existsSync(join(root, asset))).toBe(true);
  });

  it('encodes a real pairing URI into a nonblank local QR matrix', () => {
    const context: { qrcode?: (type: number, correction: string) => QrCode } = {};
    runInNewContext(readFileSync(join(root, 'vendor/qrcode.js'), 'utf8'), context);
    expect(typeof context.qrcode).toBe('function');

    const qr = context.qrcode!(0, 'M');
    qr.addData(
      'dshm://pair?v=1&bid=00000000-0000-4000-8000-000000000000' +
        '&tok=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJK&bk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG' +
        '&fp=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG',
      'Byte',
    );
    qr.make();
    const size = qr.getModuleCount();
    let dark = 0;
    for (let row = 0; row < size; row += 1) {
      for (let column = 0; column < size; column += 1) if (qr.isDark(row, column)) dark += 1;
    }
    expect(size).toBeGreaterThan(20);
    expect(dark).toBeGreaterThan(100);
    expect(dark).toBeLessThan(size * size);
  });
});
