export const shelterCreatedTemplate = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Nuevo shelter registrado</title>
  <style>
    body { margin: 0; padding: 0; background: #fafafa; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; color: #18181b; -webkit-font-smoothing: antialiased; }
    .container { max-width: 600px; margin: 0 auto; padding: 24px 16px 40px; }
    .brand { text-align: center; margin-bottom: 24px; }
    .brand__logo { font-size: 28px; font-weight: 900; color: #ff6b6b; letter-spacing: -0.02em; line-height: 1; }
    .brand__tagline { font-size: 11px; color: #a1a1aa; margin-top: 6px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; }
    .card { background: #fff; border: 1.5px solid #f0f0f0; border-radius: 20px; padding: 28px; margin-bottom: 16px; box-shadow: 0 2px 10px rgba(0,0,0,0.04); }
    .card__title { font-size: 20px; font-weight: 900; color: #18181b; margin: 0 0 20px 0; line-height: 1.3; letter-spacing: -0.01em; }
    .card__label { font-size: 11px; color: #a1a1aa; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; margin: 0 0 4px 0; }
    .card__value { font-size: 14px; color: #18181b; font-weight: 600; background: #f4f4f5; border-radius: 8px; padding: 10px 14px; margin: 0 0 16px 0; word-break: break-all; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; }
    .card__value:last-child { margin-bottom: 0; }
    .badge { display: inline-block; background: #fff5f5; border: 1.5px solid #fecdd3; color: #ff6b6b; font-size: 12px; font-weight: 800; border-radius: 999px; padding: 4px 12px; margin-bottom: 20px; }
    .footer { text-align: center; padding: 28px 16px 8px; font-size: 12px; color: #a1a1aa; line-height: 1.7; }
    .footer__brand { color: #ff6b6b; font-weight: 800; }
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">
      <div class="brand__logo">adogme</div>
      <div class="brand__tagline">refugios &middot; adopción</div>
    </div>
    <div class="card">
      <span class="badge">Nuevo shelter</span>
      <h1 class="card__title">Se registró un nuevo shelter</h1>
      <p class="card__label">User ID</p>
      <p class="card__value">{{userId}}</p>
      <p class="card__label">Email</p>
      <p class="card__value">{{userEmail}}</p>
    </div>
    <div class="footer">
      Notificación automática de <span class="footer__brand">adogme</span><br>
      La plataforma que conecta refugios con familias adoptantes.
    </div>
  </div>
</body>
</html>`;
