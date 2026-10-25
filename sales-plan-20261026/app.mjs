import { decryptBundle } from './crypto.mjs';

const form = document.getElementById('unlock-form');
const input = document.getElementById('password');
const status = document.getElementById('status');
const submit = document.getElementById('unlock-button');
const gate = document.getElementById('gate');
const view = document.getElementById('view');
const reader = document.getElementById('reader');
let assetURLs = [];
let activeAttempt = 0;

function lock() {
  activeAttempt += 1;
  reader.removeAttribute('srcdoc');
  reader.src = 'about:blank';
  for (const url of assetURLs) URL.revokeObjectURL(url);
  assetURLs = [];
  input.value = '';
  status.textContent = '';
  submit.disabled = false;
  submit.textContent = '打开报告';
  view.hidden = true;
  gate.hidden = false;
  document.body.classList.remove('unlocked');
}

function render(bundle) {
  const report = new DOMParser().parseFromString(bundle.html, 'text/html');
  // Keep the original layout, with no executable content or network-loaded scripts.
  report.querySelectorAll('script, iframe, object, embed, base').forEach((element) => element.remove());
  report.querySelectorAll('*').forEach((element) => {
    for (const attribute of [...element.attributes]) {
      if (/^on/i.test(attribute.name)) element.removeAttribute(attribute.name);
    }
  });
  const noindex = report.createElement('meta');
  noindex.name = 'robots'; noindex.content = 'noindex, nofollow, noarchive';
  report.head.append(noindex);
  const referrer = report.createElement('meta');
  referrer.name = 'referrer'; referrer.content = 'no-referrer';
  report.head.append(referrer);
  const assetMap = new Map();
  for (const asset of bundle.assets) {
    const bytes = Uint8Array.from(atob(asset.data), char => char.charCodeAt(0));
    const url = URL.createObjectURL(new Blob([bytes], { type: asset.mime }));
    assetURLs.push(url);
    assetMap.set(asset.path, url);
  }
  const localPath = value => {
    try { return decodeURIComponent(value || '').replace(/^\.\//, ''); }
    catch { return ''; }
  };
  for (const element of report.querySelectorAll('image[href], img[src]')) {
    const attr = element.localName === 'image' ? 'href' : 'src';
    const url = assetMap.get(localPath(element.getAttribute(attr)));
    if (url) element.setAttribute(attr, url);
    else element.removeAttribute(attr);
  }
  for (const link of report.querySelectorAll('a[href]')) {
    const href = link.getAttribute('href');
    const name = localPath(href);
    if (assetMap.has(name)) {
      link.href = assetMap.get(name);
      link.setAttribute('download', name);
    } else if (/^https?:\/\//i.test(href)) {
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
    } else if (!href.startsWith('#')) {
      link.removeAttribute('href');
    }
  }
  reader.removeAttribute('src');
  reader.srcdoc = '<!doctype html>' + report.documentElement.outerHTML;
  gate.hidden = true;
  view.hidden = false;
  document.body.classList.add('unlocked');
  document.getElementById('lock-button').focus();
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (submit.disabled) return;
  let password = input.value;
  if (!password) { status.textContent = '请输入阅读密码。'; input.focus(); return; }
  input.value = '';
  const attempt = ++activeAttempt;
  submit.disabled = true;
  submit.textContent = '正在打开…';
  status.textContent = '';
  try {
    if (!window.isSecureContext || !globalThis.crypto?.subtle) {
      throw new Error('UNSUPPORTED');
    }
    let envelope;
    try {
      const response = await fetch('./payload.json', { cache: 'no-store', credentials: 'omit' });
      if (!response.ok) throw new Error('load');
      envelope = await response.json();
    } catch { throw new Error('LOAD_FAILED'); }
    const bundle = await decryptBundle(envelope, password);
    password = '';
    if (attempt === activeAttempt) render(bundle);
  } catch (error) {
    if (attempt !== activeAttempt) return;
    status.textContent = error.message === 'UNSUPPORTED'
      ? '请使用支持加密功能的现代浏览器，并通过 HTTPS 链接打开。'
      : error.message === 'LOAD_FAILED'
        ? '报告暂时没有加载成功，请检查网络后重试。'
        : '密码不正确，或报告文件已损坏。请检查后重试。';
    input.focus();
  } finally {
    password = '';
    if (attempt === activeAttempt) { submit.disabled = false; submit.textContent = '打开报告'; }
  }
});
document.getElementById('lock-button').addEventListener('click', () => { lock(); input.focus(); });
window.addEventListener('pagehide', lock);
window.addEventListener('pageshow', (event) => { if (event.persisted) lock(); });
lock();
