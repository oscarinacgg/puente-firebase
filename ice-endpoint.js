// ice-endpoint.js — Ruta GET /ice para tu servidor de Render (puente-firebase)
//
// Entrega a la app los servidores ICE/TURN con credenciales TEMPORALES, así la clave
// secreta de Metered vive solo en el servidor y nunca viaja dentro del APK.
//
// Cómo usarlo (en tu servidor Express de Render, que usa Node 18 o superior):
//   1. Copia este archivo junto a tu archivo principal del servidor.
//   2. En el archivo principal, después de crear `app`, agrega:
//          app.set('trust proxy', 1);                 // Render va detrás de un proxy
//          require('./ice-endpoint')(app);
//   3. En Render -> tu servicio -> Environment, crea estas variables:
//          METERED_APP         = tecnodisca            (el nombre de tu app en Metered)
//          METERED_SECRET_KEY  = <clave secreta>       (Metered -> Dashboard -> Developers -> Secret Key)
//   4. Guarda y espera a que Render vuelva a desplegar.
//
// Prueba: abre https://puente-firebase.onrender.com/ice en el navegador;
// debe mostrar una lista con servidores turn: y turns:.

const CREDENCIAL_VALE_SEGUNDOS = 3 * 60 * 60;   // la credencial de Metered dura 3 horas
const CACHE_SERVIDOR_MS        = 60 * 60 * 1000; // el servidor reutiliza la misma durante 1 hora
const MAX_PETICIONES_POR_HORA  = 30;             // por dirección IP

module.exports = function registrarRutaIce(app) {
    let cache = { servidores: null, hasta: 0 };
    const visitas = new Map();                   // ip -> lista de momentos de petición

    function limitarPorIp(req, res, next) {
        const ahora = Date.now();
        const lista = (visitas.get(req.ip) || []).filter(t => ahora - t < 3600000);
        if (lista.length >= MAX_PETICIONES_POR_HORA) {
            return res.status(429).json({ error: 'demasiadas solicitudes' });
        }
        lista.push(ahora);
        visitas.set(req.ip, lista);
        // Limpieza ocasional para que el mapa no crezca sin límite
        if (visitas.size > 5000) {
            for (const [ip, ts] of visitas) {
                if (!ts.some(t => ahora - t < 3600000)) visitas.delete(ip);
            }
        }
        next();
    }

    app.get('/ice', limitarPorIp, async (req, res) => {
        res.set('Access-Control-Allow-Origin', '*');
        res.set('Cache-Control', 'no-store');
        try {
            if (cache.servidores && Date.now() < cache.hasta) {
                return res.json(cache.servidores);
            }

            const appName = process.env.METERED_APP;
            const secreto = process.env.METERED_SECRET_KEY;
            if (!appName || !secreto) throw new Error('faltan METERED_APP o METERED_SECRET_KEY');

            const base = `https://${appName}.metered.live/api/v1/turn`;

            // 1) Crear una credencial que se vence sola
            const rCred = await fetch(`${base}/credential?secretKey=${encodeURIComponent(secreto)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ expiryInSeconds: CREDENCIAL_VALE_SEGUNDOS, label: 'beep-baseball' })
            });
            if (!rCred.ok) throw new Error('Metered credential: HTTP ' + rCred.status);
            const cred = await rCred.json();

            // 2) Pedir la lista de servidores ICE de esa credencial
            const rIce = await fetch(`${base}/credentials?apiKey=${encodeURIComponent(cred.apiKey)}`);
            if (!rIce.ok) throw new Error('Metered credentials: HTTP ' + rIce.status);
            const servidores = await rIce.json();
            if (!Array.isArray(servidores) || servidores.length === 0) throw new Error('lista vacía');

            cache = { servidores, hasta: Date.now() + CACHE_SERVIDOR_MS };
            res.json(servidores);
        } catch (e) {
            console.error('Ruta /ice falló:', e.message);
            res.status(502).json({ error: 'no disponible' });   // la app usará su respaldo público
        }
    });
};
