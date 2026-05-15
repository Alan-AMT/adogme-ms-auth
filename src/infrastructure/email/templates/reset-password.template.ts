export const resetPasswordTemplate = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Restablecer contraseña</title>
  <style>
    body { margin: 0; padding: 0; background: #fafafa; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; color: #18181b; -webkit-font-smoothing: antialiased; }
    a { color: #ff6b6b; text-decoration: none; }
    .container { max-width: 600px; margin: 0 auto; padding: 24px 16px 40px; }
    .brand { text-align: center; margin-bottom: 24px; }
    .brand__logo { font-size: 28px; font-weight: 900; color: #ff6b6b; letter-spacing: -0.02em; line-height: 1; }
    .brand__tagline { font-size: 11px; color: #a1a1aa; margin-top: 6px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; }
    .intro { background: #fff; border: 1.5px solid #f0f0f0; border-radius: 20px; padding: 24px; margin-bottom: 16px; box-shadow: 0 2px 10px rgba(0,0,0,0.04); }
    .intro__hi { font-size: 14px; color: #71717a; margin: 0 0 6px 0; font-weight: 600; }
    .intro__title { font-size: 20px; font-weight: 900; color: #18181b; margin: 0 0 10px 0; line-height: 1.3; letter-spacing: -0.01em; }
    .intro__desc { font-size: 14px; color: #52525b; margin: 0; line-height: 1.6; }
    .intro__strong { color: #ff6b6b; font-weight: 800; }
    .notice { background: #fff5f5; border: 1.5px solid #fecdd3; border-radius: 16px; padding: 14px 18px; margin-bottom: 16px; font-size: 13px; color: #71717a; line-height: 1.6; }
    .notice strong { color: #18181b; font-weight: 700; }
    .cta { text-align: center; margin: 24px 0 8px; }
    .cta__btn { display: inline-block; padding: 14px 36px; background: #ff6b6b; color: #ffffff !important; font-size: 15px; font-weight: 800; border-radius: 999px; text-decoration: none; letter-spacing: 0.01em; box-shadow: 0 4px 14px rgba(255,107,107,0.35); }
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
    <div class="intro">
      <p class="intro__hi">Hola <span class="intro__strong">{{name}}</span>,</p>
      <h1 class="intro__title">Restablecer contraseña</h1>
      <p class="intro__desc">
        Recibimos una solicitud para restablecer la contraseña de tu cuenta en
        <span class="intro__strong">adogme</span>. Haz clic en el botón de abajo para crear una nueva contraseña.
      </p>
    </div>
    <div class="notice">
      <strong>Este enlace expirará en 15 minutos.</strong> Si no solicitaste restablecer tu contraseña, puedes ignorar este correo de forma segura.
    </div>
    <div class="cta">
      <a href="{{url}}" class="cta__btn">Restablecer contraseña</a>
    </div>
    <div class="footer">
      Este correo fue enviado por <span class="footer__brand">adogme</span><br>
      La plataforma que conecta refugios con familias adoptantes.
    </div>
  </div>
</body>
</html>`;
