/* 通行密钥（WebAuthn）前端：base64url 与 ArrayBuffer 互转，调浏览器 API，结果交给后端验证。 */
(function () {
  function b2a(buf) { var s = '', b = new Uint8Array(buf); for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function a2b(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; var r = atob(s), b = new Uint8Array(r.length); for (var i = 0; i < r.length; i++) b[i] = r.charCodeAt(i); return b.buffer; }
  function post(url, body) { return fetch(url, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }).then(function (r) { return r.json().then(function (j) { if (!r.ok || j.ok === false) { if (j.reauth) location.href = j.reauth; throw new Error(j.error || ('HTTP ' + r.status)); } return j; }); }); }
  function fail(e) { if (e && e.name === 'NotAllowedError') return; alert('通行密钥：' + (e && e.message || e)); }
  window.pkRegister = function (optUrl, verUrl, name) {
    if (!window.PublicKeyCredential) return alert('这个浏览器不支持通行密钥');
    post(optUrl).then(function (o) {
      o.challenge = a2b(o.challenge); o.user.id = a2b(o.user.id);
      (o.excludeCredentials || []).forEach(function (c) { c.id = a2b(c.id); });
      return navigator.credentials.create({ publicKey: o });
    }).then(function (c) {
      var cred = { id: c.id, rawId: b2a(c.rawId), type: c.type, response: { clientDataJSON: b2a(c.response.clientDataJSON), attestationObject: b2a(c.response.attestationObject), transports: c.response.getTransports ? c.response.getTransports() : [] }, clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {} };
      return post(verUrl, { credential: cred, name: name || '' });
    }).then(function () { location.reload(); }).catch(fail);
  };
  window.pkAuth = function (optUrl, verUrl, next) {
    if (!window.PublicKeyCredential) return alert('这个浏览器不支持通行密钥');
    post(optUrl).then(function (o) {
      o.challenge = a2b(o.challenge);
      (o.allowCredentials || []).forEach(function (c) { c.id = a2b(c.id); });
      return navigator.credentials.get({ publicKey: o });
    }).then(function (c) {
      var r = c.response, cred = { id: c.id, rawId: b2a(c.rawId), type: c.type, response: { clientDataJSON: b2a(r.clientDataJSON), authenticatorData: b2a(r.authenticatorData), signature: b2a(r.signature), userHandle: r.userHandle ? b2a(r.userHandle) : null }, clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {} };
      return post(verUrl, { credential: cred, next: next || '' });
    }).then(function (j) { location.href = j.next; }).catch(fail);
  };
})();
