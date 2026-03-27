/**
 * StallTCP1.3修复版 (动态UUID适配)
 * 修复日常的小数据请求更重要的逻辑问题。
 * 修复下载队列在长期频繁的峰值状态会导致上传队列被阻塞问题。
 * 适配了ProxyIP使用， 路径格式，/proxyip=ip:port
 * 适配了动态UUID逻辑，使用 HMAC-SHA256 签名和时间戳验证。
 * 🫡致敬原版作者：Alexandre_Kojeve
 * 天诚技术交流群@zyssadmin出品
 */

import { connect } from 'cloudflare:sockets';

// --- 动态 UUID 逻辑 (来自 1.3代理(动态UUID).js) ---
class DynamicUUID {
	constructor(secretKey, expirationInSeconds = 24 * 60 * 60) {
		if (!secretKey) throw new Error('A secretKey is required.');
		this.secretKey = secretKey;
		this.expirationInSeconds = expirationInSeconds;
		this.encoder = new TextEncoder();
	}
	async _getImportedKey() {
		if (!this._importedKey) {
			this._importedKey = await crypto.subtle.importKey('raw', this.encoder.encode(this.secretKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
		}
		return this._importedKey;
	}
	async _sign(data) {
		const key = await this._getImportedKey();
		return crypto.subtle.sign('HMAC', key, data);
	}
	_bytesToUUID(bytes) {
		const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
		return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20,32)}`;
	}
	_uuidToBytes(uuidString) {
		const hex = uuidString.replace(/-/g, '');
		if (hex.length !== 32) return null;
		const bytes = new Uint8Array(16);
		for (let i = 0; i < 16; i++) {
			bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
		}
		return bytes;
	}
	async generate() {
		const nowInSeconds = Math.floor(Date.now() / 1000);
		const randomBytes = crypto.getRandomValues(new Uint8Array(4));
		const payload = new Uint8Array(8);
		const view = new DataView(payload.buffer);
		view.setUint32(0, nowInSeconds, false);
		payload.set(randomBytes, 4);
		const signature = await this._sign(payload);
		const signaturePart = new Uint8Array(signature.slice(0, 8));
		const uuidBytes = new Uint8Array(16);
		uuidBytes.set(payload, 0);
		uuidBytes.set(signaturePart, 8);
		return this._bytesToUUID(uuidBytes);
	}
	async validate(uuidString) {
		const uuidBytes = this._uuidToBytes(uuidString);
		if (!uuidBytes) return false;
		const payload = uuidBytes.slice(0, 8);
		const signaturePart = uuidBytes.slice(8, 16);
		const expectedSignature = await this._sign(payload);
		const expectedSignaturePart = new Uint8Array(expectedSignature.slice(0, 8));
		if (signaturePart.length !== expectedSignaturePart.length) return false;
		let diff = 0;
		for (let i = 0; i < signaturePart.length; i++) {
			diff |= signaturePart[i] ^ expectedSignaturePart[i];
		}
		if (diff !== 0) return false;
		const view = new DataView(payload.buffer);
		const timestamp = view.getUint32(0, false);
		const nowInSeconds = Math.floor(Date.now() / 1000);
		if (nowInSeconds - timestamp > this.expirationInSeconds) return false;
		return true;
	}
}

// 动态 UUID 配置
const UUID_SECRET_KEY = 'YT2d8b0652-7757-433fS8350-e72087b9bc45OD'; 
const UUID_EXPIRATION_SECONDS = 3 * 24 * 60 * 60; // 3 天有效期

// 核心常量
const MAX_PENDING = 2097152, KEEPALIVE = 15000, STALL_TO = 8000, MAX_STALL = 12, MAX_RECONN = 24;

// 辅助函数 (来自 StallTCP1.3修复版.js 和 1.3代理(动态UUID).js)
const buildUUID = (a, i) => Array.from(a.slice(i, i + 16)).map(n => n.toString(16).padStart(2, '0')).join('').replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
const extractAddr = b => {
  const o1 = 18 + b[17] + 1, p = (b[o1] << 8) | b[o1 + 1], t = b[o1 + 2]; let o2 = o1 + 3, h, l;
  switch (t) {
    case 1: l = 4; h = b.slice(o2, o2 + l).join('.'); break;
    case 2: l = b[o2++]; h = new TextDecoder().decode(b.slice(o2, o2 + l)); break;
    case 3: l = 16; h = `[${Array.from({ length: 8 }, (_, i) => ((b[o2 + i * 2] << 8) | b[o2 + i * 2 + 1]).toString(16)).join(':')}]`; break;
    default: throw new Error('Invalid address type.');
  } return { host: h, port: p, payload: b.slice(o2 + l) };
};
const parseAddressPort = (addressSegment) => {
  let address, port;
  if (addressSegment.startsWith('[')) {
    const [ipv6Address, portStr = 443] = addressSegment.slice(1, -1).split(']:');
    address = `[${ipv6Address}]`; port = portStr;
  } else { 
    [address, port = 443] = addressSegment.split(':'); 
  } 
  return [address, port];
}

class Pool {
  constructor() { this.buf = new ArrayBuffer(16384); this.ptr = 0; this.pool = []; this.max = 8; this.large = false; }
  alloc = s => {
    if (s <= 4096 && s <= 16384 - this.ptr) { const v = new Uint8Array(this.buf, this.ptr, s); this.ptr += s; return v; } const r = this.pool.pop();
    if (r && r.byteLength >= s) return new Uint8Array(r.buffer, 0, s); return new Uint8Array(s);
  };
  free = b => {
    if (b.buffer === this.buf) { this.ptr = Math.max(0, this.ptr - b.length); return; }
    if (this.pool.length < this.max && b.byteLength >= 1024) this.pool.push(b);
  }; enableLarge = () => { this.large = true; }; reset = () => { this.ptr = 0; this.pool.length = 0; this.large = false; };
}

export default {
  async fetch(r) { 
    if (r.headers.get('Upgrade') !== 'websocket') return new Response('OK', { status: 200 });
    
    const u = new URL(r.url); 
    let proxyIPConfig = null;
    if (u.pathname.includes('/proxyip=')) {
      try {
        const proxyParam = u.pathname.split('/proxyip=')[1].split('/')[0];
        const [address, port] = parseAddressPort(proxyParam); 
        proxyIPConfig = { address, port: +port }; 
      } catch (e) {
        console.error('Failed to parse proxyip:', e.message);
      }
    }
    
    const { 0: c, 1: s } = new WebSocketPair(); s.accept(); s.send(new Uint8Array([0, 0])); 
    handle(s, proxyIPConfig); 
    return new Response(null, { status: 101, webSocket: c });}
};

const handle = (ws, proxyIPConfig) => {
  // 实例 DynamicUUID 
  const dynamicUUID = new DynamicUUID(UUID_SECRET_KEY, UUID_EXPIRATION_SECONDS);

  const pool = new Pool(); let sock, w, r, info, first = true, rxBytes = 0, stalls = 0, reconns = 0;
  let lastAct = Date.now(), conn = false, reading = false, writing = false; 
  const tmrs = {}, pend = [];
  let pendBytes = 0, score = 1.0, lastChk = Date.now(), lastRx = 0, succ = 0, fail = 0;
  let stats = { tot: 0, cnt: 0, big: 0, win: 0, ts: Date.now() }; 
  
  // --- 模式优化部分 (来自 StallTCP1.3修复版.js) ---
  let mode = 'buffered', avgSz = 0, tputs = [];

  const updateMode = s => {
    stats.tot += s; stats.cnt++; if (s > 8192) stats.big++; avgSz = avgSz * 0.9 + s * 0.1; const now = Date.now();
    if (now - stats.ts > 1000) {
      const rate = stats.win; tputs.push(rate); if (tputs.length > 5) tputs.shift(); stats.win = s; stats.ts = now;
      const avg = tputs.reduce((a, b) => a + b, 0) / tputs.length;
      if (stats.cnt >= 20) {
        // 反转逻辑：大流量/大包 -> direct (零拷贝)
        if (avg > 20971520 && avgSz > 16384) { 
          if (mode !== 'direct') { mode = 'direct'; } 
        }
        // 小流量/小包 -> buffered (合并)
        else if (avg < 10485760 || avgSz < 8192) { 
          if (mode !== 'buffered') { mode = 'buffered'; pool.enableLarge(); } 
        }
        // 中间 -> adaptive
        else { 
          if (mode !== 'adaptive') mode = 'adaptive'; 
        }
      }} else { stats.win += s; }
  };
  
  const readLoop = async () => {
    if (reading) return; reading = true; let batch = [], bSz = 0, bTmr = null;
    const flush = () => {
      if (!bSz) return; const m = new Uint8Array(bSz); let p = 0;
      for (const c of batch) { m.set(c, p); p += c.length; }
      if (ws.readyState === 1) ws.send(m);
      batch = []; bSz = 0; if (bTmr) { clearTimeout(bTmr); bTmr = null; }
    };
    try {
      while (true) {
        // 上传队列反压
        if (pendBytes > MAX_PENDING) { await new Promise(res => setTimeout(res, 100)); continue; }
        const { done, value: v } = await r.read();
        if (v?.length) {
          rxBytes += v.length; lastAct = Date.now(); stalls = 0; updateMode(v.length); const now = Date.now();
          if (now - lastChk > 5000) {
            const el = now - lastChk, by = rxBytes - lastRx, tp = by / el;
            if (tp > 500) score = Math.min(1.0, score + 0.05);
            else if (tp < 50) score = Math.max(0.1, score - 0.05);
            lastChk = now; lastRx = rxBytes;
          }
          if (mode === 'buffered') {
            if (v.length < 32768) {
              batch.push(v); bSz += v.length;
              if (bSz >= 131072) flush();
              else if (!bTmr) bTmr = setTimeout(flush, avgSz > 16384 ? 5 : 20);
            } else { flush(); if (ws.readyState === 1) ws.send(v); }
          } else if (mode === 'adaptive') {
            if (v.length < 4096) {
              batch.push(v); bSz += v.length;
              if (bSz >= 32768) flush();
              else if (!bTmr) bTmr = setTimeout(flush, 15);
            } else { flush(); if (ws.readyState === 1) ws.send(v); }
          } else { // mode === 'direct'
            flush(); if (ws.readyState === 1) ws.send(v); 
          }
        } if (done) { flush(); reading = false; reconn(); break; }
      }} catch (e) { flush(); if (bTmr) clearTimeout(bTmr); reading = false; fail++; reconn(); }
  };

  // --- 上传循环/反压修复 (来自 StallTCP1.3修复版.js) ---
  const writeLoop = async () => {
    if (writing) return; 
    writing = true;
    try {
      while(writing) { 
        if (!w) { 
          await new Promise(res => setTimeout(res, 100));
          continue;
        }
        if (pend.length === 0) { 
          await new Promise(res => setTimeout(res, 20));
          continue;
        }
        
        const b = pend.shift();
        await w.write(b); 
        pendBytes -= b.length; 
        pool.free(b);
      }
    } catch (e) {
      writing = false;
      // 写入失败由 keepalive/reconn 处理
    }
  };

  const attemptConnection = async () => {
    const connectionMethods = ['direct'];
    if (proxyIPConfig) {
      connectionMethods.push('proxy');
    }
    let lastError;
    // 尝试所有连接方式
    for (const method of connectionMethods) {
      try {
        const connectOpts = (method === 'direct')
          ? { hostname: info.host, port: info.port }
          : { hostname: proxyIPConfig.address, port: proxyIPConfig.port };
        
        const sock = connect(connectOpts);
        await sock.opened;
        return sock;
      } catch (e) {
        lastError = e;
      }
    }
    throw lastError || new Error('All connection methods failed.');
  };

  const establish = async () => { 
    try {
      sock = await attemptConnection(); 
      w = sock.writable.getWriter(); r = sock.readable.getReader(); 
      // 启动读写循环
      conn = false; reconns = 0; score = Math.min(1.0, score + 0.15); succ++; lastAct = Date.now(); 
      readLoop();
      writeLoop();
    } catch (e) { 
      conn = false; fail++; score = Math.max(0.1, score - 0.2); 
      reconn(); 
    }
  };

  const reconn = async () => {
    if (!info || ws.readyState !== 1) { cleanup(); ws.close(1011, 'Invalid.'); return; }
    if (reconns >= MAX_RECONN) { cleanup(); ws.close(1011, 'Max reconnect.'); return; }
    if (score < 0.3 && reconns > 5 && Math.random() > 0.6) { cleanup(); ws.close(1011, 'Poor network.'); return; }
    if (conn) return; reconns++; let d = Math.min(50 * Math.pow(1.5, reconns - 1), 3000);
    d *= (1.5 - score * 0.5); d += (Math.random() - 0.5) * d * 0.2; d = Math.max(50, Math.floor(d));
    try {
      cleanSock();
      if (pendBytes > MAX_PENDING * 2) {
        while (pendBytes > MAX_PENDING && pend.length > 5) { const drop = pend.shift(); pendBytes -= drop.length; pool.free(drop); }
      }
      await new Promise(res => setTimeout(res, d)); conn = true;
      
      sock = await attemptConnection(); 

      w = sock.writable.getWriter(); r = sock.readable.getReader();
      conn = false; reconns = 0; score = Math.min(1.0, score + 0.15); succ++; stalls = 0; lastAct = Date.now(); 
      readLoop();
      writeLoop(); 
    } catch (e) { 
      conn = false; fail++; score = Math.max(0.1, score - 0.2);
      if (reconns < MAX_RECONN && ws.readyState === 1) setTimeout(reconn, 500);
      else { cleanup(); ws.close(1011, 'Exhausted.'); }
    }
  };

  const startTmrs = () => {
    tmrs.ka = setInterval(async () => {
      if (!conn && w && Date.now() - lastAct > KEEPALIVE) { try { await w.write(new Uint8Array(0)); lastAct = Date.now(); } catch (e) { reconn(); }}
    }, KEEPALIVE / 3);
    tmrs.hc = setInterval(() => {
      if (!conn && stats.tot > 0 && Date.now() - lastAct > STALL_TO) { stalls++;
        if (stalls >= MAX_STALL) {
          if (reconns < MAX_RECONN) { stalls = 0; reconn(); }
          else { cleanup(); ws.close(1011, 'Stall.'); }
        }}}, STALL_TO / 2);
  };
  
  const cleanSock = () => { 
    reading = false; 
    writing = false; // 停止 writeLoop
    try { w?.releaseLock(); r?.releaseLock(); sock?.close(); } catch {} 
  };
  
  const cleanup = () => {
    Object.values(tmrs).forEach(clearInterval); cleanSock();
    while (pend.length) pool.free(pend.shift());
    pendBytes = 0; stats = { tot: 0, cnt: 0, big: 0, win: 0, ts: Date.now() };
    mode = 'buffered'; // 重置回 buffered
    avgSz = 0; tputs = []; pool.reset();
  };
  
  ws.addEventListener('message', async e => {
    try {
      if (first) {
        first = false; const b = new Uint8Array(e.data);
        
        // --- 动态 UUID 授权检查 (替换原版硬编码 UUID) ---
        const receivedUUIDString = buildUUID(b, 1);
        const isValid = await dynamicUUID.validate(receivedUUIDString);
        if (!isValid) throw new Error('Auth failed: Invalid or expired dynamic UUID.');
        // --- END 动态 UUID 授权检查 ---

        const { host, port, payload } = extractAddr(b); 
        info = { host, port }; 
        conn = true; 
        if (payload.length) { const buf = pool.alloc(payload.length); buf.set(payload); pend.push(buf); pendBytes += buf.length; } 
        startTmrs(); 
        establish(); 
      } else { 
        // --- 上传数据处理 (来自 StallTCP1.3修复版.js) ---
        lastAct = Date.now();
        
        // 为上传队列设置硬上限 (约 4MB)，防止内存耗尽
        if (pendBytes > MAX_PENDING * 2) { 
          console.log('Upload buffer full, dropping packet');
          return; // 丢弃新包
        }
        
        const buf = pool.alloc(e.data.byteLength); 
        buf.set(new Uint8Array(e.data)); 
        pend.push(buf); 
        pendBytes += buf.length;
        // --- END 上传数据处理 ---
      }
    } catch (err) { 
      cleanup(); ws.close(1006, 'Error.'); 
    }
  }); 
  
  ws.addEventListener('close', cleanup); ws.addEventListener('error', cleanup);
};
