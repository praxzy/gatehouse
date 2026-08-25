package httpapp

const pageTemplates = `
{{define "header"}}
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}} · Northstar Employee Portal</title>
  <style>
    :root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, sans-serif; color: #17251d; background: #f4f2e9; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; background: radial-gradient(circle at 85% 10%, #dbe9db 0, transparent 30rem), #f4f2e9; }
    header { display: flex; align-items: center; justify-content: space-between; padding: 1.15rem clamp(1rem, 5vw, 4.5rem); border-bottom: 1px solid #d8d8cb; background: rgba(250,249,243,.82); }
    .brand { display: flex; align-items: center; gap: .75rem; color: #173f2a; font-weight: 760; letter-spacing: -.02em; }
    .mark { display: grid; place-items: center; width: 2rem; height: 2rem; border-radius: .65rem; color: #f8f7ef; background: #17663d; font-size: .85rem; }
    nav { display: flex; align-items: center; gap: .85rem; }
    a { color: #17663d; font-weight: 650; text-decoration: none; }
    main { width: min(68rem, calc(100% - 2rem)); margin: clamp(2.5rem, 8vw, 7rem) auto; }
    .hero, .panel { border: 1px solid #d3d8cd; border-radius: 1.5rem; background: rgba(255,255,250,.9); box-shadow: 0 24px 70px rgba(30,58,42,.09); }
    .hero { display: grid; grid-template-columns: 1.4fr .8fr; overflow: hidden; }
    .copy { padding: clamp(2rem, 6vw, 5rem); }
    .eyebrow { margin: 0 0 1rem; color: #46705a; font-size: .75rem; font-weight: 780; letter-spacing: .17em; text-transform: uppercase; }
    h1 { max-width: 13ch; margin: 0; font-family: Georgia, serif; font-size: clamp(2.7rem, 7vw, 5.8rem); font-weight: 500; line-height: .98; letter-spacing: -.045em; }
    .lede { max-width: 34rem; margin: 1.5rem 0 2rem; color: #5a675f; font-size: 1.05rem; line-height: 1.7; }
    .aside { display: flex; flex-direction: column; justify-content: flex-end; min-height: 25rem; padding: 2rem; color: #eaf3ea; background: #123b28; }
    .button { display: inline-flex; width: fit-content; align-items: center; justify-content: center; border: 0; border-radius: 999px; padding: .78rem 1.15rem; color: white; background: #17663d; font: inherit; font-weight: 720; cursor: pointer; }
    .button.secondary { color: #173f2a; background: #e1ebe2; }
    .identity { display: grid; gap: .75rem; }
    .identity strong { font-size: 1.35rem; }
    .identity span { color: #b9cbbc; }
    .roles { display: flex; flex-wrap: wrap; gap: .45rem; margin-top: .6rem; }
    .role { border: 1px solid #6b8d76; border-radius: 999px; padding: .3rem .6rem; color: #dce9df; font-size: .78rem; }
    .actions { display: flex; flex-wrap: wrap; gap: .75rem; margin-top: 1.4rem; }
    form { display: inline; }
    .panel { max-width: 45rem; padding: clamp(2rem, 6vw, 4.5rem); }
    .panel h1 { font-size: clamp(2.5rem, 6vw, 4.5rem); }
    .status { color: #667069; font-variant-numeric: tabular-nums; }
    footer { padding: 2rem; color: #788178; text-align: center; font-size: .8rem; }
    @media (max-width: 720px) { .hero { grid-template-columns: 1fr; } .aside { min-height: auto; } header { align-items: flex-start; } nav { flex-wrap: wrap; justify-content: flex-end; } }
  </style>
</head>
<body>
<header>
  <div class="brand"><span class="mark">NS</span>Northstar Portal</div>
  <nav><a href="/">Home</a>{{if .SignedIn}}<a href="/admin">Admin</a><form action="/logout" method="post"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button class="button secondary" type="submit">Sign out</button></form>{{end}}</nav>
</header>
{{end}}

{{define "footer"}}<footer>Employee access powered by Gatehouse · {{.CurrentYear}}</footer></body></html>{{end}}

{{define "home"}}
{{template "header" .}}
<main>
  <section class="hero">
    <div class="copy">
      <p class="eyebrow">Northstar · People operations</p>
      {{if .SignedIn}}
      <h1>Welcome back, {{.Identity.Name}}.</h1>
      <p class="lede">Your employee workspace is ready. This portal created its own local session only after independently validating Gatehouse's issuer, audience, nonce, expiry, and RS256 signature.</p>
      <div class="actions"><a class="button" href="/admin">Open admin workspace</a></div>
      {{else}}
      <h1>Everything your workday needs.</h1>
      <p class="lede">Sign in through your organization's Gatehouse identity to reach the Northstar employee workspace.</p>
      <a class="button" href="/login">Continue with Gatehouse</a>
      {{end}}
    </div>
    <aside class="aside">
      {{if .SignedIn}}
      <div class="identity"><span>Signed in as</span><strong>{{.Identity.Email}}</strong><span>Verified roles</span><div class="roles">{{range .Identity.Roles}}<span class="role">{{.}}</span>{{end}}</div></div>
      {{else}}
      <p class="eyebrow">Single sign-on</p><strong>One identity. One secure handoff. No password handled by this portal.</strong>
      {{end}}
    </aside>
  </section>
</main>
{{template "footer" .}}
{{end}}

{{define "admin"}}
{{template "header" .}}
<main><section class="panel"><p class="eyebrow">Role-protected route</p><h1>Admin workspace</h1><p class="lede">This page is available because the independently verified ID token contains the exact <strong>Admin</strong> role for {{.Identity.Email}}.</p><a href="/">Return home</a></section></main>
{{template "footer" .}}
{{end}}

{{define "error"}}
{{template "header" .}}
<main><section class="panel"><p class="eyebrow">Employee Portal</p><h1>{{.Title}}</h1><p class="lede">{{.Message}}</p><p class="status">Status {{.Status}}</p><a class="button" href="/">Return to the portal</a></section></main>
{{template "footer" .}}
{{end}}
`
