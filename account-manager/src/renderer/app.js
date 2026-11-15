'use strict'

const api = window.manager
const model = {
  accounts: [],
  proxies: [],
  bindings: [],
  settings: {},
  events: [],
  selectedAccountId: null,
  encryptionAvailable: false,
  search: '',
  status: 'all',
  view: 'accounts',
  refreshSequence: 0
}

const $ = (selector) => document.querySelector(selector)
const $$ = (selector) => [...document.querySelectorAll(selector)]

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]))
}

function formatTime(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString('zh-CN', { hour12: false })
}

function initials(account) {
  const source = account.label || account.email || account.profileName || '?'
  return source.trim().slice(0, 1).toUpperCase()
}

function proxyFor(account) {
  return model.proxies.find((proxy) => proxy.id === account.proxyId) || null
}

function showToast(message, kind = 'ok') {
  const node = document.createElement('div')
  node.className = `toast${kind === 'error' ? ' error' : ''}`
  node.textContent = message
  $('#toast-root').appendChild(node)
  setTimeout(() => node.remove(), 3600)
}

function setBusy(button, busy) {
  if (!button) return
  button.disabled = busy
  if (busy) {
    button.dataset.oldText = button.textContent
    button.textContent = '处理中…'
  } else if (button.dataset.oldText) {
    button.textContent = button.dataset.oldText
    delete button.dataset.oldText
  }
}

async function withBusy(button, task) {
  setBusy(button, true)
  try { return await task() } catch (error) { showToast(error.message || String(error), 'error'); throw error } finally { setBusy(button, false) }
}

async function refresh() {
  const sequence = ++model.refreshSequence
  const [snapshot, pool] = await Promise.all([api.getState(), api.listProxies()])
  if (sequence !== model.refreshSequence) return
  model.accounts = snapshot.accounts || []
  model.settings = snapshot.settings || {}
  model.events = snapshot.events || []
  model.selectedAccountId = snapshot.selectedAccountId
  model.encryptionAvailable = Boolean(snapshot.encryptionAvailable)
  model.proxies = pool.proxies || []
  model.bindings = pool.bindings || []
  renderAll()
}

function renderAll() {
  $('#security-state').textContent = model.encryptionAvailable ? 'DPAPI 加密可用' : '未检测到系统加密'
  $('#security-state').style.color = model.encryptionAvailable ? 'var(--accent)' : 'var(--warn)'
  $('#runtime-root').textContent = model.projectRoot || '—'
  $('#profile-count').textContent = String(model.accounts.length)
  $('#proxy-count').textContent = String(model.proxies.filter((proxy) => proxy.enabled).length)
  renderAccounts()
  renderProxies()
  renderSettings()
  renderActivity()
}

function renderAccounts() {
  const active = model.accounts.filter((account) => account.status === 'running').length
  const loggedIn = model.accounts.filter((account) => account.session?.authenticated === true).length
  const bound = model.accounts.filter((account) => account.proxyId).length
  $('#account-metrics').innerHTML = [
    ['账号总数', model.accounts.length, ''],
    ['运行中', active, 'accent'],
    ['已保存会话', loggedIn, 'accent'],
    ['已绑定代理', bound, '']
  ].map(([label, value, cls]) => `<div class="metric"><div class="metric-label">${label}</div><div class="metric-value ${cls}">${value}</div></div>`).join('')

  const enabledProxyCount = model.proxies.filter((proxy) => proxy.enabled).length
  const capacity = enabledProxyCount * Number(model.settings.accountsPerProxy || 2)
  const occupied = model.proxies.filter((proxy) => proxy.enabled).reduce((total, proxy) => total + proxy.accountCount, 0)
  const available = model.proxies.filter((proxy) => proxy.enabled)
    .reduce((total, proxy) => total + Math.max(0, Number(model.settings.accountsPerProxy || 2) - proxy.accountCount), 0)
  $('#account-capacity').textContent = enabledProxyCount ? `全局绑定 ${occupied}/${capacity} · 可用空位 ${available}` : '暂无启用代理'
  const search = model.search.toLowerCase()
  const rows = model.accounts.filter((account) => {
    const haystack = `${account.label} ${account.email} ${account.profileName}`.toLowerCase()
    const searchHit = !search || haystack.includes(search)
    const statusHit = model.status === 'all' || account.status === model.status
    return searchHit && statusHit
  })
  $('#account-rows').innerHTML = rows.length ? rows.map(renderAccountRow).join('') : '<tr><td colspan="7"><div class="empty">暂无账号，点击“新建账号”开始。</div></td></tr>'
}

function statusText(status) {
  return ({ running: '运行中', starting: '启动中', 'logged-in': 'Cookie快照', 'auth-pending': '待登录', ready: '待启动', error: '错误' }[status] || '待启动')
}

function renderAccountRow(account) {
  const proxy = proxyFor(account)
  const session = account.session || {}
  const image = session.deviceImage || {}
  const imageLabel = image.timezone && image.locale ? `${image.timezone} · ${image.locale}` : '画像未记录'
  const loginLabel = session.authenticated ? '重新登录' : '首次登录'
  const action = account.status === 'running'
    ? `<button class="row-action" data-action="stop-account" data-id="${escapeHtml(account.id)}">停止</button>`
    : account.status === 'starting'
      ? '<button class="row-action primary" type="button" disabled>启动中…</button>'
    : `<button class="row-action primary" data-action="activate-account" data-id="${escapeHtml(account.id)}">启动</button>`
  return `<tr>
    <td><div class="account-name"><span class="avatar">${escapeHtml(initials(account))}</span><div><strong>${escapeHtml(account.label || account.profileName)}</strong><span>${escapeHtml(account.email || '未填写邮箱')}</span></div></div></td>
    <td><div class="profile-cell"><b>${escapeHtml(account.profileName)}</b><span>${account.runtimePid ? `PID ${escapeHtml(account.runtimePid)}` : escapeHtml(imageLabel)}</span></div></td>
    <td><div class="proxy-cell"><b>${proxy ? escapeHtml(proxy.displayUrl) : '未绑定'}</b><span>${proxy ? escapeHtml(proxy.id) : '登录与启动禁止直连'}</span></div></td>
    <td><div class="proxy-cell"><b>${session.authenticated ? '本地 Cookie 快照' : (session.cookieCount ? `${session.cookieCount} Cookies` : '无快照')}</b><span>${session.savedAt ? escapeHtml(formatTime(session.savedAt)) : '未保存'}</span></div></td>
    <td><span class="status ${escapeHtml(account.status)}">${statusText(account.status)}</span></td>
    <td class="muted mono">${escapeHtml(formatTime(account.lastUsedAt))}</td>
    <td><div class="row-actions">${action}<button class="row-action" data-action="login-account" data-id="${escapeHtml(account.id)}">${loginLabel}</button><button class="row-action" data-action="edit-account" data-id="${escapeHtml(account.id)}">编辑</button><button class="row-action danger" data-action="delete-account" data-id="${escapeHtml(account.id)}">删除</button></div></td>
  </tr>`
}

function renderProxies() {
  const enabled = model.proxies.filter((proxy) => proxy.enabled).length
  const totalBindings = model.bindings.length
  const capacity = enabled * Number(model.settings.accountsPerProxy || 2)
  $('#proxy-metrics').innerHTML = [
    ['启用代理', enabled, 'accent'],
    ['绑定关系', totalBindings, ''],
    ['硬容量', capacity, ''],
    ['告警阈值', enabled * Number(model.settings.warningMultiplier || 2), '']
  ].map(([label, value, cls]) => `<div class="metric"><div class="metric-label">${label}</div><div class="metric-value ${cls}">${value}</div></div>`).join('')
  $('#proxy-rows').innerHTML = model.proxies.length ? model.proxies.map((proxy) => {
    const state = proxy.enabled ? '启用' : '停用'
    const load = `${proxy.accountCount}/${Number(model.settings.accountsPerProxy || 2)}`
    return `<tr><td><div class="profile-cell"><b>${escapeHtml(proxy.displayUrl)}</b><span class="mono">${escapeHtml(proxy.id)}</span></div></td><td><span class="status ${proxy.enabled ? 'logged-in' : ''}">${state}</span></td><td class="mono">${load}</td><td class="muted mono">${escapeHtml(proxy.lastChecked ? formatTime(proxy.lastChecked) : '未验活')}</td><td><div class="row-actions"><button class="row-action" data-action="test-proxy" data-id="${escapeHtml(proxy.id)}">验活</button><button class="row-action danger" data-action="remove-proxy" data-id="${escapeHtml(proxy.id)}">删除</button></div></td></tr>`
  }).join('') : '<tr><td colspan="5"><div class="empty">暂无代理，点击“添加 SOCKS5”。</div></td></tr>'
  $('#binding-rows').innerHTML = model.bindings.length ? model.bindings.map((binding) => `<div class="binding-item"><span>${escapeHtml(binding.accountKey)}</span><b>${escapeHtml(binding.proxyId)}</b></div>`).join('') : '<div class="empty">暂无绑定关系。</div>'
}

function renderSettings() {
  const form = $('#settings-form')
  if (!form || document.activeElement?.form === form) return
  form.elements.desktopExe.value = model.settings.desktopExe || ''
  form.elements.loginUrl.value = model.settings.loginUrl || 'https://claude.ai/login'
  form.elements.accountsPerProxy.value = model.settings.accountsPerProxy || 2
  form.elements.warningMultiplier.value = model.settings.warningMultiplier || 2
  form.elements.autoBind.checked = model.settings.autoBind !== false
  form.elements.launchInject.checked = true
  form.elements.launchFingerprint.checked = true
}

function renderActivity() {
  $('#activity-log').innerHTML = model.events.length ? model.events.slice().reverse().map((event) => `<div class="activity-line ${escapeHtml(event.level)}"><span class="time">${escapeHtml(formatTime(event.time))}</span><span>${escapeHtml(event.message)}</span></div>`).join('') : '<div class="muted">暂无活动</div>'
}

function closeModal() {
  $('#modal-root').innerHTML = ''
}

function nextProfileName() {
  const used = new Set(model.accounts.map((account) => String(account.profileName || '').toLowerCase()))
  let index = 1
  while (used.has(String(index))) index++
  return String(index)
}

function openAccountModal(existing = null) {
  const emptyProxyLabel = existing
    ? '解除当前绑定（锁定画像不变）'
    : '自动分配首个 SOCKS5（创建画像必需）'
  const proxyOptions = [`<option value="">${emptyProxyLabel}</option>`, ...model.proxies.filter((proxy) => proxy.enabled).map((proxy) => `<option value="${escapeHtml(proxy.id)}" ${existing?.proxyId === proxy.id ? 'selected' : ''}>${escapeHtml(proxy.displayUrl)} · ${escapeHtml(proxy.id)}</option>`)].join('')
  const profileName = existing?.profileName || nextProfileName()
  $('#modal-root').innerHTML = `<div class="modal-backdrop" data-modal-close><div class="modal" role="dialog" aria-modal="true"><h2>${existing ? '编辑账号' : '新建账号'}</h2><form id="account-form"><label>显示名称<input name="label" maxlength="80" required value="${escapeHtml(existing?.label || '')}"></label><label>邮箱<input name="email" type="email" maxlength="320" value="${escapeHtml(existing?.email || '')}"></label><div class="form-grid"><label>Profile 名称<input name="profileName" maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,63}" required value="${escapeHtml(profileName)}"></label><label>SOCKS5 绑定<select name="proxyId">${proxyOptions}</select></label></div><label>网页登录地址<input name="loginUrl" type="url" required value="${escapeHtml(existing?.loginUrl || model.settings.loginUrl || 'https://claude.ai/login')}"></label><label>备注<textarea name="notes" maxlength="2000">${escapeHtml(existing?.notes || '')}</textarea></label><label class="check-row"><input name="enabled" type="checkbox" ${existing?.enabled !== false ? 'checked' : ''}><span>账号启用</span></label>${existing ? '' : '<label class="check-row"><input name="openLoginAfterSave" type="checkbox" checked><span>保存后打开网页登录</span></label>'}<div id="account-form-error" class="modal-error"></div><div class="modal-actions"><button class="button secondary" type="button" data-modal-close>取消</button><button class="button primary" type="submit">保存账号</button></div></form></div></div>`
  const backdrop = $('.modal-backdrop')
  backdrop.addEventListener('click', (event) => { if (event.target === backdrop || event.target.matches('[data-modal-close]')) closeModal() })
  $('#account-form').addEventListener('submit', async (event) => {
    event.preventDefault()
    const form = event.currentTarget
    const submit = form.querySelector('button[type="submit"]')
    await withBusy(submit, async () => {
      try {
        const saved = await api.saveAccount({
          id: existing?.id,
          label: form.elements.label.value,
          email: form.elements.email.value,
          profileName: form.elements.profileName.value,
          proxyId: form.elements.proxyId.value || null,
          loginUrl: form.elements.loginUrl.value,
          notes: form.elements.notes.value,
          enabled: form.elements.enabled.checked
        })
        const openLoginAfterSave = !existing && Boolean(form.elements.openLoginAfterSave?.checked)
        closeModal()
        await refresh()
        if (openLoginAfterSave) {
          openLoginModal(saved)
          showToast('账号已创建，请先完成网页登录')
        } else {
          showToast(existing ? '账号已更新' : '账号已创建')
        }
      } catch (error) {
        $('#account-form-error').textContent = error.message || String(error)
        throw error
      }
    }).catch(() => undefined)
  })
}

function openLoginModal(account) {
  const proxy = proxyFor(account)
  const image = account.session?.deviceImage || {}
  const imageLabel = image.timezone && image.locale ? `${image.timezone} · ${image.locale}` : '未锁定'
  $('#modal-root').innerHTML = `<div class="modal-backdrop"><div class="modal modal-wide" role="dialog" aria-modal="true"><h2>网页登录 · ${escapeHtml(account.label || account.profileName)}</h2><p>网页登录窗口使用该账号的独立会话、锁定画像和绑定 SOCKS5；代理检查未通过时禁止加载页面。</p><div class="login-meta"><span>Profile <b>${escapeHtml(account.profileName)}</b></span><span>画像 <b>${escapeHtml(imageLabel)}</b></span><span>代理 <b>${escapeHtml(proxy?.displayUrl || '未绑定')}</b></span></div><form id="login-form"><label>登录页地址<input name="loginUrl" type="url" value="${escapeHtml(account.loginUrl || model.settings.loginUrl || 'https://claude.ai/login')}" required></label><label>完整 Magic Link<textarea name="magicLink" rows="4" placeholder="https://claude.ai/magic-link#..."></textarea></label><div id="login-proxy-audit" class="modal-note">未检查代理</div><div id="login-form-error" class="modal-error"></div><div class="modal-actions"><button class="button secondary" id="cancel-login" type="button">取消</button><button class="button secondary" id="check-login-proxy" type="button">检查代理</button><button class="button secondary" id="open-login-page" type="button">打开登录页</button><button class="button primary" id="open-magic-link" type="button">打开 Magic Link</button></div></form></div></div>`
  const errorNode = $('#login-form-error')
  const auditNode = $('#login-proxy-audit')
  const form = $('#login-form')
  const egressLabel = (result) => {
    const ip2 = result?.ip2Location
    if (!ip2?.externalIp) return `IPify ${result.externalIp}${ip2?.error ? ' · IP2Location 未确认' : ''}`
    return `IPify ${result.externalIp} · IP2Location ${ip2.externalIp}${ip2.sameAsIpify ? '（同一出口）' : '（双栈出口）'}`
  }
  let loginActionPending = false
  const runLoginAction = async (button, task) => {
    if (loginActionPending) return
    loginActionPending = true
    try { await withBusy(button, task) } catch { } finally { loginActionPending = false }
  }
  $('#cancel-login').addEventListener('click', (event) => runLoginAction(event.currentTarget, async () => {
    await api.closeLogin()
    closeModal()
  }))
  form.addEventListener('submit', (event) => event.preventDefault())

  const openTarget = (button, target) => runLoginAction(button, async () => {
    try {
      const result = await api.openLogin(account.id, target)
      auditNode.textContent = `代理正常：${egressLabel(result)} · Native PID ${result.nativePid} · ${result.dnsMode}${result.target === 'Magic Link' ? ' · 登录状态待确认' : ''}`
      errorNode.textContent = ''
      if (result.target === 'Magic Link') form.elements.magicLink.value = ''
      showToast(result.target === 'Magic Link'
        ? 'Magic Link 已提交到当前登录窗口；尚未确认登录，请查看页面和事件日志'
        : (result.navigated ? `${result.target} 已打开，出口 ${result.proxy}` : '已显示当前登录窗口，代理会话保持不变'))
    } catch (error) {
      errorNode.textContent = error.message || String(error)
      throw error
    }
  })

  $('#open-login-page').addEventListener('click', (event) => openTarget(event.currentTarget, form.elements.loginUrl.value))
  $('#open-magic-link').addEventListener('click', (event) => openTarget(event.currentTarget, form.elements.magicLink.value))
  $('#check-login-proxy').addEventListener('click', (event) => runLoginAction(event.currentTarget, async () => {
    try {
      const result = await api.checkLoginProxy(account.id)
      auditNode.textContent = `代理正常：${egressLabel(result)} · ${result.latencyMs}ms · ${result.dnsMode}`
      errorNode.textContent = ''
      showToast(`网页登录代理正常：${egressLabel(result)}`)
    } catch (error) {
      errorNode.textContent = error.message || String(error)
      throw error
    }
  }))
}

function openProxyModal() {
  $('#modal-root').innerHTML = `<div class="modal-backdrop" data-modal-close><div class="modal modal-wide" role="dialog" aria-modal="true"><h2>添加 SOCKS5 代理</h2><p>支持批量粘贴，每行一条；自动识别 URL、host:port:user:pass、host|port|user|pass、host,port,user,pass 和 JSON 列表。</p><form id="proxy-form"><label>代理地址<textarea name="url" rows="8" placeholder="socks5h://user:pass@host:1080 | host:port:user:pass" required></textarea></label><div id="proxy-form-error" class="modal-error"></div><div class="modal-actions"><button class="button secondary" type="button" data-modal-close>取消</button><button class="button primary" type="submit">识别并导入</button></div></form></div></div>`
  const backdrop = $('.modal-backdrop')
  backdrop.addEventListener('click', (event) => { if (event.target === backdrop || event.target.matches('[data-modal-close]')) closeModal() })
  $('#proxy-form').addEventListener('submit', async (event) => {
    event.preventDefault()
    const form = event.currentTarget
    const submit = form.querySelector('button[type="submit"]')
    await withBusy(submit, async () => {
      try {
        const result = await api.addProxy(form.elements.url.value)
        closeModal()
        await refresh()
        const skipped = (result.errors?.length || 0) + (result.duplicates?.length || 0) + (result.failed?.length || 0)
        showToast(`\u5df2\u5bfc\u5165 ${result.added?.length || 0} \u6761\u4ee3\u7406${skipped ? `\uff0c\u8df3\u8fc7 ${skipped} \u6761` : ''}`, skipped ? 'error' : 'ok')
      } catch (error) {
        $('#proxy-form-error').textContent = error.message || String(error)
        throw error
      }
    }).catch(() => undefined)
  })
}

function openExportModal() {
  $('#modal-root').innerHTML = `<div class="modal-backdrop" data-modal-close><div class="modal" role="dialog" aria-modal="true"><h2>导出账号 JSON</h2><p>默认导出不含 Cookie 值。包含会话时写入本机 DPAPI 加密快照，换 Windows 用户后不能直接解密。</p><div class="modal-actions"><button class="button secondary" type="button" data-modal-close>取消</button><button class="button secondary" type="button" data-export="metadata">仅导出元数据</button><button class="button primary" type="button" data-export="secure">包含加密会话</button></div></div></div>`
  const backdrop = $('.modal-backdrop')
  backdrop.addEventListener('click', (event) => { if (event.target === backdrop || event.target.matches('[data-modal-close]')) closeModal() })
  $$('[data-export]').forEach((button) => button.addEventListener('click', async () => {
    await withBusy(button, async () => {
      const result = await api.exportAccounts({ includeSecrets: button.dataset.export === 'secure' })
      closeModal()
      if (!result.canceled) showToast(`已导出 ${result.count} 个账号`)
    }).catch(() => undefined)
  }))
}

function setView(view) {
  model.view = view
  $$('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.view === view))
  $$('.view').forEach((item) => item.classList.toggle('active-view', item.id === `view-${view}`))
}

async function handleAccountAction(action, id, button) {
  const account = model.accounts.find((item) => item.id === id)
  if (!account) return
  if (action === 'edit-account') return openAccountModal(account)
  if (action === 'activate-account') {
    await withBusy(button, async () => { await api.activateAccount(id); await refresh(); showToast('Desktop 已启动') }).catch(() => undefined)
    return
  }
  if (action === 'stop-account') {
    await withBusy(button, async () => { await api.stopAccount(id); await refresh(); showToast('Profile 已停止') }).catch(() => undefined)
    return
  }
  if (action === 'login-account') {
    openLoginModal(account)
    return
  }
  if (action === 'delete-account') {
    if (!window.confirm(`彻底删除“${account.label || account.profileName}”？账号、登录态、Cookies、缓存、代理绑定和整个 Profile 画像都会永久删除。`)) return
    await withBusy(button, async () => { await api.deleteAccount(id); await refresh(); showToast('账号和 Profile 已彻底删除') }).catch(() => undefined)
  }
}

async function handleProxyAction(action, id, button) {
  if (action === 'test-proxy') {
    await withBusy(button, async () => {
      const result = await api.testProxy(id)
      const target = result.claude?.challenge
        ? '脚本探针遇 403 验证，浏览器结果未判定'
        : result.claude?.httpOk
          ? `脚本探针 Claude HTTP ${result.claude.statusCode}`
          : `脚本探针 Claude ${result.claude?.statusCode ? `HTTP ${result.claude.statusCode}` : '连接失败'}，浏览器结果未判定`
      const ip2 = result.ip2Location
      const egress = ip2?.externalIp
        ? `IPify ${result.externalIp} · IP2Location ${ip2.externalIp}${ip2.sameAsIpify ? '' : '（双栈）'}`
        : `IPify ${result.externalIp}`
      showToast(`SOCKS5 ${egress} · ${target}`)
      await refresh()
    }).catch(() => undefined)
    return
  }
  if (action === 'remove-proxy') {
    if (!window.confirm('删除此代理并解除关联？')) return
    await withBusy(button, async () => { await api.removeProxy(id); await refresh(); showToast('代理已删除') }).catch(() => undefined)
  }
}

function registerEvents() {
  $$('.nav-item').forEach((item) => item.addEventListener('click', () => setView(item.dataset.view)))
  document.addEventListener('click', async (event) => {
    const actionNode = event.target.closest('[data-action]')
    if (!actionNode) return
    const action = actionNode.dataset.action
    if (action === 'refresh') {
      await withBusy(actionNode, refresh).catch(() => undefined)
      return
    }
    if (action === 'open-data') { await api.openPath('data'); return }
    if (action === 'open-runtime') { await api.openPath('runtime'); return }
    if (action === 'add-account') { openAccountModal(); return }
    if (action === 'edit-account' || action === 'activate-account' || action === 'stop-account' || action === 'login-account' || action === 'delete-account') {
      await handleAccountAction(action, actionNode.dataset.id, actionNode)
      return
    }
    if (action === 'import') {
      await withBusy(actionNode, async () => { const result = await api.importAccounts(); if (!result.canceled) { await refresh(); showToast(`导入完成：新增 ${result.added}，更新 ${result.updated}`) } }).catch(() => undefined)
      return
    }
    if (action === 'export') { openExportModal(); return }
    if (action === 'add-proxy') { openProxyModal(); return }
    if (action === 'test-proxy' || action === 'remove-proxy') { await handleProxyAction(action, actionNode.dataset.id, actionNode) }
  })
  $('#account-search').addEventListener('input', (event) => { model.search = event.target.value; renderAccounts() })
  $('#status-filter').addEventListener('change', (event) => { model.status = event.target.value; renderAccounts() })
  $('#settings-form').addEventListener('submit', async (event) => {
    event.preventDefault()
    const form = event.currentTarget
    const submit = form.querySelector('button[type="submit"]')
    await withBusy(submit, async () => {
      await api.saveSettings({
        desktopExe: form.elements.desktopExe.value,
        loginUrl: form.elements.loginUrl.value,
        accountsPerProxy: form.elements.accountsPerProxy.value,
        warningMultiplier: form.elements.warningMultiplier.value,
        autoBind: form.elements.autoBind.checked,
        launchInject: form.elements.launchInject.checked,
        launchFingerprint: form.elements.launchFingerprint.checked
      })
      await refresh()
      showToast('设置已保存')
    }).catch(() => undefined)
  })
  api.onEvent((event) => {
    model.events.push(event)
    model.events = model.events.slice(-100)
    renderActivity()
    void refresh().catch(() => undefined)
  })
}

async function init() {
  registerEvents()
  try { await refresh() } catch (error) { showToast(error.message || String(error), 'error') }
}

document.addEventListener('DOMContentLoaded', init)
