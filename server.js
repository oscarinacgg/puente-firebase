// server.js - Puente (proxy) de Firebase Auth para Render.
// Recibe las peticiones de inicio de sesión del juego y las reenvía a Google desde la IP de Render.
// No tiene dependencias: solo usa módulos que ya trae Node.
//
// Rutas que acepta: /<host-de-google>/<ruta>?key=<API_KEY>
// Ejemplo: /identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key=...
// Solo reenvía a los hosts de la lista y solo si la clave (key) es la de tu proyecto.

'use strict';
const http = require('http');
const https = require('https');

const PORT = Number(process.env.PORT || 10000);
// Clave pública de tu proyecto Firebase (la misma apiKey de servicios.js).
// Se puede cambiar en Render con la variable de entorno FIREBASE_API_KEY.
const API_KEY = process.env.FIREBASE_API_KEY || 'AIzaSyAt_XVMLb8GofAchhn4wED3vf-N8Ke76vA';
const LIMITE_POR_MINUTO = Number(process.env.LIMITE_POR_MINUTO || 300); // por IP
const MAX_BODY = 64 * 1024;   // 64 KB: más que suficiente para un inicio de sesión
const TIMEOUT_MS = 25000;

// host permitido -> expresión que debe cumplir la ruta (null = cualquier ruta)
const HOSTS = new Map([
  ['identitytoolkit.googleapis.com', null],
  ['securetoken.googleapis.com', null],
  ['www.googleapis.com', /^\/identitytoolkit\//]
]);

// Cabeceras que NO se reenvían a Google (privacidad y limpieza)
const NO_REENVIAR = /^(host|connection|keep-alive|transfer-encoding|upgrade|te|trailer|proxy-.*|accept-encoding|content-length|cookie|forwarded|x-forwarded-.*|x-real-ip|true-client-ip|cf-.*|rndr-.*|render-.*|x-request-start)$/i;
// Cabeceras de la respuesta de Google que NO se devuelven al juego
const NO_DEVOLVER = /^(access-control-.*|alt-svc|set-cookie|connection|keep-alive|transfer-encoding|content-length)$/i;

// ---- Límite simple de peticiones por IP ----
const contadores = new Map();
function ipDe(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return req.socket.remoteAddress || 'desconocida';
}
function excedeLimite(ip) {
  const ahora = Date.now();
  let c = contadores.get(ip);
  if (!c || ahora - c.inicio > 60000) { c = { inicio: ahora, n: 0 }; contadores.set(ip, c); }
  c.n++;
  return c.n > LIMITE_POR_MINUTO;
}
setInterval(() => {
  const ahora = Date.now();
  for (const [ip, c] of contadores) if (ahora - c.inicio > 60000) contadores.delete(ip);
}, 60000).unref();


function ponerCORS(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || '*');
  res.setHeader('Access-Control-Max-Age', '86400');
}

function responder(res, codigo, texto) {
  res.writeHead(codigo, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify({ error: { code: codigo, message: texto } }));
}

const servidor = http.createServer((req, res) => {
  ponerCORS(req, res);

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  let url;
  try { url = new URL(req.url, 'http://puente.local'); } catch (e) { return responder(res, 400, 'Dirección no válida'); }

  // Para despertar el servicio y comprobar que responde
  if (url.pathname === '/' || url.pathname === '/ping') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end('ok');
    return;
  }

  if (req.method !== 'GET' && req.method !== 'POST') return responder(res, 405, 'Método no permitido');

  const partes = url.pathname.split('/');            // ['', host, ...ruta]
  const host = partes[1] || '';
  const ruta = '/' + partes.slice(2).join('/');
  if (!HOSTS.has(host)) return responder(res, 404, 'Destino no permitido');
  const patron = HOSTS.get(host);
  if (patron && !patron.test(ruta)) return responder(res, 403, 'Ruta no permitida');
  if (url.searchParams.get('key') !== API_KEY) return responder(res, 403, 'Clave no válida');
  if (excedeLimite(ipDe(req))) return responder(res, 429, 'Demasiadas peticiones. Espera un minuto.');

  // Se lee el cuerpo completo (es pequeño) con límite de tamaño
  const trozos = [];
  let total = 0;
  let cortado = false;
  req.on('data', (t) => {
    if (cortado) return;
    total += t.length;
    if (total > MAX_BODY) { cortado = true; responder(res, 413, 'Petición demasiado grande'); req.destroy(); return; }
    trozos.push(t);
  });
  req.on('error', () => {});
  req.on('end', () => {
    if (cortado) return;
    const cuerpo = Buffer.concat(trozos);

    const cabeceras = {};
    for (const [nombre, valor] of Object.entries(req.headers)) {
      if (!NO_REENVIAR.test(nombre)) cabeceras[nombre] = valor;
    }
    if (cuerpo.length > 0) cabeceras['content-length'] = String(cuerpo.length);

    const destino = https.request({
      host: host,
      port: 443,
      method: req.method,
      path: ruta + url.search,
      headers: cabeceras,
      timeout: TIMEOUT_MS
    }, (resp) => {
      const salida = {};
      for (const [nombre, valor] of Object.entries(resp.headers)) {
        if (!NO_DEVOLVER.test(nombre)) salida[nombre] = valor;
      }
      salida['cache-control'] = 'no-store';
      res.writeHead(resp.statusCode || 502, salida);
      resp.pipe(res);
      console.log(req.method + ' ' + host + ruta + ' -> ' + resp.statusCode); // sin cuerpo ni parámetros
    });
    destino.on('timeout', () => { destino.destroy(new Error('timeout')); });
    destino.on('error', (e) => {
      console.warn('Error hacia Google (' + host + '): ' + e.message);
      if (!res.headersSent) responder(res, e.message === 'timeout' ? 504 : 502, 'No se pudo contactar a Google desde el puente');
      else res.end();
    });
    if (cuerpo.length > 0) destino.write(cuerpo);
    destino.end();
  });
});

servidor.keepAliveTimeout = 65000;
servidor.listen(PORT, () => console.log('Puente de Firebase escuchando en el puerto ' + PORT));
