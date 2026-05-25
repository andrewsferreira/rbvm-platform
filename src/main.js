// =============================================================================
// RBVM Platform — Entry Point (Boot com try/catch explícito)
// © 2026 Andrews Ferreira. Todos os direitos reservados.
// =============================================================================

console.info('[RBVM] main.js loaded — booting application');

function showBootError(error) {
  const main = document.getElementById('main');
  const status = document.getElementById('boot-status');
  if (status) status.textContent = '⚠ Erro de inicialização';
  if (main) {
    main.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:center;height:100%;flex-direction:column;gap:14px;padding:40px;text-align:center">
        <i class="ti ti-alert-triangle" style="font-size:52px;color:var(--high)"></i>
        <div style="font-size:17px;font-weight:700;color:var(--text)">Application failed to start</div>
        <div style="font-size:13px;color:var(--text2);max-width:420px;line-height:1.6">
          Ocorreu um erro durante a inicialização dos módulos da plataforma.<br>
          Isso pode ser causado por um import quebrado, dado inválido ou erro de sintaxe.
        </div>
        <div style="background:var(--bg3);border:1px solid var(--border2);border-radius:var(--r);padding:10px 16px;font-size:11px;font-family:monospace;color:var(--high);max-width:480px;word-break:break-all">
          ${error?.message || String(error)}
        </div>
        <div style="font-size:11px;color:var(--text3)">Abra <strong>DevTools → Console</strong> (F12) para detalhes técnicos.</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:center;margin-top:8px">
          <button onclick="location.reload()" style="padding:8px 16px;background:var(--accent);color:#fff;border:none;border-radius:var(--r);cursor:pointer;font-size:12px">
            ↺ Recarregar
          </button>
          <button onclick="localStorage.clear();location.reload()" style="padding:8px 16px;background:var(--bg3);color:var(--text2);border:1px solid var(--border2);border-radius:var(--r);cursor:pointer;font-size:12px">
            Limpar Cache e Recarregar
          </button>
        </div>
        <div style="font-size:10px;color:var(--text3);margin-top:4px">
          GitHub Pages · ${new Date().toISOString()}
        </div>
      </div>`;
  }
}

async function boot() {
  try {
    const status = document.getElementById('boot-status');
    if (status) status.textContent = 'Importando módulos...';

    const { initApp } = await import('./app.js');

    if (status) status.textContent = 'Inicializando aplicação...';
    console.info('[RBVM] app.js imported — calling initApp()');

    await initApp();

    console.info('[RBVM] boot complete ✓');
  } catch (error) {
    console.error('[RBVM] boot failed:', error);
    showBootError(error);
  }
}

boot();
