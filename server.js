// server.js - Puente (proxy) de Firebase Auth para Render.
// Recibe las peticiones de inicio de sesión del juego y las reenvía a Google desde la IP de Render.
// No tiene dependencias: solo usa módulos que ya trae Node.
//
// Rutas que acepta: /<host-de-google>/<ruta>
// 1) Inicio de sesión (Firebase Auth):  ?key=<API_KEY>
//    Ejemplo: /identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key=...
// 2) Base de datos (Realtime Database, API REST):  ?auth=<token de sesión del usuario>
//    Ejemplo: /beep-baseball-default-rtdb.firebaseio.com/jugadores/UID/estadisticas.json?auth=...
// Solo reenvía a los hosts de la lista. Las reglas de seguridad de tu base de datos siguen mandando:
// el puente no abre nada que Firebase no permita ya al usuario con sesión iniciada.

'use strict';
const http = require('http');
const https = require('https');

const PORT = Number(process.env.PORT || 10000);
// Clave pública de tu proyecto Firebase (la misma apiKey de servicios.js).
// Se puede cambiar en Render con la variable de entorno FIREBASE_API_KEY.
const API_KEY = process.env.FIREBASE_API_KEY || 'AIzaSyAt_XVMLb8GofAchhn4wED3vf-N8Ke76vA';
// Proyecto y base de datos de Firebase (cámbialos con variables de entorno en Render si hace falta)
const PROJECT_ID = process.env.FIREBASE_PROJECT_ID || 'beep-baseball';
const DB_HOST = process.env.FIREBASE_DB_HOST || (PROJECT_ID + '-default-rtdb.firebaseio.com');
const LIMITE_POR_MINUTO = Number(process.env.LIMITE_POR_MINUTO || 300); // por IP
const MAX_BODY = 64 * 1024;   // 64 KB: más que suficiente para un inicio de sesión
const TIMEOUT_MS = 25000;

// host permitido -> expresión que debe cumplir la ruta (null = cualquier ruta)
const HOSTS = new Map([
  ['identitytoolkit.googleapis.com', null],
  ['securetoken.googleapis.com', null],
  ['www.googleapis.com', /^\/identitytoolkit\//],
  [DB_HOST, /\.json$/]          // base de datos: solo rutas de la API REST (terminan en .json)
]);

// Cabeceras que NO se reenvían a Google (privacidad y limpieza)
const NO_REENVIAR = /^(host|connection|keep-alive|transfer-encoding|upgrade|te|trailer|proxy-.*|accept-encoding|content-length|cookie|forwarded|x-forwarded-.*|x-real-ip|true-client-ip|cf-.*|rndr-.*|render-.*|x-request-start)$/i;
// Cabeceras de la respuesta de Google que NO se devuelven al juego
const NO_DEVOLVER = /^(access-control-.*|alt-svc|set-cookie|connection|keep-alive|transfer-encoding|content-length)$/i;

// ---- Servidores TURN (ruta /ice) ----
// La clave secreta de Metered se lee solo aquí, de las variables de Render. Nunca se envía al juego.
const METERED_APP = process.env.METERED_APP || '';
const METERED_SECRET_KEY = process.env.METERED_SECRET_KEY || '';
const ICE_CREDENCIAL_SEG = 3 * 60 * 60;   // la credencial temporal de Metered dura 3 horas
const ICE_CACHE_MS = 60 * 60 * 1000;      // se reutiliza la misma lista durante 1 hora
let iceCache = { servidores: null, hasta: 0 };

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
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Expose-Headers', 'ETag');
  res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || '*');
  res.setHeader('Access-Control-Max-Age', '86400');
}

// El "auth" de la base de datos debe parecer un token de sesión de TU proyecto (la validación real la hace Firebase)
function tokenDeMiProyecto(token) {
  if (!/^[\w-]+\.[\w-]+\.[\w-]+$/.test(token || '')) return false;
  try {
    const datos = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString('utf8'));
    return datos.aud === PROJECT_ID;
  } catch (e) { return false; }
}

function responder(res, codigo, texto) {
  res.writeHead(codigo, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify({ error: { code: codigo, message: texto } }));
}

// Llamada HTTPS a Metered que devuelve el JSON. No muestra la clave en los errores.
function pedirAMetered(metodo, ruta, cuerpo) {
  return new Promise((resolver, rechazar) => {
    const datos = cuerpo ? Buffer.from(JSON.stringify(cuerpo)) : null;
    const cabeceras = { 'Content-Type': 'application/json' };
    if (datos) cabeceras['Content-Length'] = String(datos.length);
    const peticion = https.request({
      host: METERED_APP + '.metered.live',
      port: 443,
      method: metodo,
      path: '/api/v1/turn/' + ruta,
      headers: cabeceras,
      timeout: 10000
    }, (resp) => {
      let texto = '';
      resp.setEncoding('utf8');
      resp.on('data', (t) => { texto += t; });
      resp.on('end', () => {
        if (resp.statusCode !== 200) return rechazar(new Error('Metered respondió ' + resp.statusCode));
        try { resolver(JSON.parse(texto)); } catch (e) { rechazar(new Error('respuesta no válida')); }
      });
    });
    peticion.on('timeout', () => peticion.destroy(new Error('tiempo agotado')));
    peticion.on('error', (e) => rechazar(new Error(e.message)));
    if (datos) peticion.write(datos);
    peticion.end();
  });
}

async function responderIce(req, res) {
  if (req.method !== 'GET') return responder(res, 405, 'Método no permitido');
  if (excedeLimite(ipDe(req))) return responder(res, 429, 'Demasiadas peticiones. Espera un minuto.');

  if (iceCache.servidores && Date.now() < iceCache.hasta) {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(JSON.stringify(iceCache.servidores));
  }
  if (!METERED_APP || !METERED_SECRET_KEY) {
    console.warn('Ruta /ice: faltan METERED_APP o METERED_SECRET_KEY en Render');
    return responder(res, 502, 'no disponible. Motivo: faltan variables METERED_APP o METERED_SECRET_KEY en Render');
  }
  try {
    const cred = await pedirAMetered('POST', 'credential?secretKey=' + encodeURIComponent(METERED_SECRET_KEY),
      { expiryInSeconds: ICE_CREDENCIAL_SEG, label: 'beep-baseball' });
    if (!cred || !cred.apiKey) throw new Error('credencial sin apiKey');
    const lista = await pedirAMetered('GET', 'credentials?apiKey=' + encodeURIComponent(cred.apiKey), null);
    if (!Array.isArray(lista) || lista.length === 0) throw new Error('lista de servidores vacía');
    iceCache = { servidores: lista, hasta: Date.now() + ICE_CACHE_MS };
    console.log('Ruta /ice: ' + lista.length + ' servidores entregados');
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(lista));
  } catch (e) {
    console.warn('Ruta /ice falló: ' + e.message);
    responder(res, 502, 'no disponible. Motivo: ' + e.message);
  }
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

  if (url.pathname === '/ice') { responderIce(req, res); return; }

  const partes = url.pathname.split('/');            // ['', host, ...ruta]
  const host = partes[1] || '';
  const ruta = '/' + partes.slice(2).join('/');
  if (!HOSTS.has(host)) return responder(res, 404, 'Destino no permitido');
  const esBaseDeDatos = (host === DB_HOST);
  const metodosOk = esBaseDeDatos ? ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] : ['GET', 'POST'];
  if (!metodosOk.includes(req.method)) return responder(res, 405, 'Método no permitido');
  const patron = HOSTS.get(host);
  if (patron && !patron.test(ruta)) return responder(res, 403, 'Ruta no permitida');
  if (esBaseDeDatos) {
    if (!tokenDeMiProyecto(url.searchParams.get('auth'))) return responder(res, 403, 'Sesión no válida');
  } else if (url.searchParams.get('key') !== API_KEY) {
    return responder(res, 403, 'Clave no válida');
  }
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
      console.log(req.method + ' ' + host + (esBaseDeDatos ? '/…' : ruta) + ' -> ' + resp.statusCode); // sin cuerpo, sin parámetros y sin rutas de usuarios
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
