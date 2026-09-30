let ownerToken = '';
let connectionEpoch = 0;
let overviewSnapshot = '';
let lastDevices = [];
let pairingExpiresAt = 0;
let pairingDeviceIds = new Set();
let noticeKind = '';
const verifiedFingerprints = new Set();
const policyStates = new Map();
const $ = (id) => document.getElementById(id);

const stateLabels = {
  CREATED: 'Preparing',
  INSPECTING: 'Preparing',
  POLICY_EVALUATING: 'Checking policy',
  CLASSIFYING: 'Checking eligibility',
  AWAITING_APPROVAL: 'Waiting for approval',
  AUTHORIZED: 'Approved',
  EXECUTING: 'Signing in',
  VERIFYING: 'Verifying account',
  SUCCEEDED: 'Signed in',
  DENIED: 'Denied',
  FAILED: 'Failed',
  EXPIRED: 'Expired',
  CANCELLED: 'Cancelled',
  INTERACTION_REQUIRED: 'Needs attention',
  OUTCOME_UNKNOWN: 'Outcome unknown',
};
const completedStates = new Set(['SUCCEEDED', 'DENIED', 'FAILED', 'EXPIRED', 'CANCELLED']);
const errorLabels = {
  CALLER_MISMATCH:
    'The owner token was not accepted. Disconnect and reconnect with your owner token.',
  INVALID_STATE: 'This item has changed. Refreshing the latest state may resolve it.',
  POLICY_DENIED: 'The broker did not allow this action.',
  NOT_FOUND: 'This item is no longer available.',
  INVALID_ARGUMENT: 'The broker could not accept this action.',
  SECURITY_STATE_UNPERSISTED:
    'Security settings could not be saved. Check the broker before retrying.',
};
const modeCopy = {
  manual: ['Manual', 'Every login needs your phone approval.'],
  safe: ['Safe', 'Eligibility check, then your phone approval.'],
  auto: ['Auto', 'Only an exact existing owner delegation can skip phone approval.'],
};

function notice(message, kind = 'info') {
  $('notice').textContent = message;
  $('notice').hidden = !message;
  $('notice').classList.toggle('error', kind === 'error');
  noticeKind = message ? kind : '';
}
function showError(error) {
  notice(
    Object.hasOwn(errorLabels, error.code)
      ? errorLabels[error.code]
      : 'Connection interrupted. Check your broker; this tab will retry.',
    'error',
  );
}
function connectionStatus(devices) {
  const pending = devices.some((device) => device.status === 'PENDING_CONFIRMATION');
  const active = devices.some((device) => device.status === 'ACTIVE');
  $('connection-status').textContent = pending
    ? 'Device confirmation needed'
    : active
      ? 'Ready'
      : 'iPhone setup needed';
  $('connection-status').classList.toggle('ready', active && !pending);
}
async function api(path, method = 'GET', body = {}) {
  const response = await fetch(path, {
    method,
    headers: {
      Authorization: `Bearer ${ownerToken}`,
      ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
    },
    ...(method === 'POST' ? { body: JSON.stringify(body) } : {}),
  });
  const data = await response.json();
  if (!response.ok) {
    const error = new Error('Owner request failed');
    error.code = typeof data.error === 'string' ? data.error : '';
    throw error;
  }
  return data;
}
function text(tag, value, className) {
  const element = document.createElement(tag);
  element.textContent = value;
  if (className) element.className = className;
  return element;
}
function action(label, callback, className = 'secondary') {
  const button = text('button', label, className);
  button.type = 'button';
  button.onclick = async () => {
    const epoch = connectionEpoch;
    button.disabled = true;
    try {
      await callback();
      await refresh();
    } catch (error) {
      if (epoch === connectionEpoch) showError(error);
    } finally {
      button.disabled = false;
    }
  };
  return button;
}
function disclosure(label, key) {
  const details = text('details', '', 'item-details');
  details.dataset.detailKey = key;
  details.append(text('summary', label));
  return details;
}
function validPolicy(policy) {
  return (
    policy &&
    typeof policy.id === 'string' &&
    policy.id.length > 0 &&
    Object.hasOwn(modeCopy, policy.mode) &&
    Number.isSafeInteger(policy.version) &&
    policy.version > 0 &&
    typeof policy.enabled === 'boolean' &&
    typeof policy.auto_delegation_available === 'boolean'
  );
}
function policyIsChanged(entry) {
  return entry.draftMode !== undefined && entry.draftMode !== entry.current.mode;
}
function updatePolicyControls(entry) {
  const policy = entry.current;
  const mode = entry.draftMode ?? policy.mode;
  const changed = policyIsChanged(entry);
  const needsReview = changed && (entry.stale || entry.forceReview);
  entry.currentLabel.textContent = `Current: ${modeCopy[policy.mode][0]}`;
  for (const [value, input] of entry.inputs) {
    input.checked = value === mode;
    input.disabled = entry.saving || !policy.enabled;
    input.parentElement.classList.toggle('selected', input.checked);
  }
  entry.description.textContent = modeCopy[mode][1];
  entry.autoNotice.hidden = mode !== 'auto';
  entry.autoNotice.textContent = policy.auto_delegation_available
    ? 'Only requests covered by an existing exact owner delegation skip phone approval. Others are blocked. This change does not create, expand or renew a delegation.'
    : 'Auto requests are blocked without a matching owner delegation. Applying Auto does not create, expand or renew one.';
  entry.review.hidden = !changed;
  entry.reviewTitle.textContent = `Change ${modeCopy[policy.mode][0]} → ${modeCopy[mode][0]}`;
  entry.apply.textContent = entry.saving ? 'Applying…' : 'Apply change';
  entry.apply.disabled = entry.saving || !policy.enabled || needsReview;
  entry.reviewLatest.hidden = !needsReview;
  entry.reviewLatest.disabled = entry.saving || !policy.enabled;
  entry.cancel.disabled = entry.saving;
  entry.message.textContent =
    entry.messageText ||
    (needsReview
      ? 'The policy changed. Review its latest state before applying your draft.'
      : !policy.enabled
        ? 'This policy is disabled.'
        : '');
  entry.message.hidden = !entry.message.textContent;
  entry.metadata.textContent = `Policy ${policy.id} · version ${policy.version}`;
}
function acceptPolicy(entry, policy) {
  if (!validPolicy(policy) || policy.id !== entry.current.id)
    throw new Error('Invalid policy response');
  // An older in-flight overview must not undo a newly confirmed server version.
  if (policy.version < entry.current.version) return;
  if (policy.version === entry.current.version && policy.mode !== entry.current.mode)
    throw new Error('Invalid policy response');
  entry.current = { ...policy };
  if (entry.draftMode !== undefined && policy.mode === entry.draftMode) {
    entry.draftMode = undefined;
    entry.expectedVersion = undefined;
    entry.stale = false;
    entry.forceReview = false;
  }
  if (policyIsChanged(entry) && entry.expectedVersion !== policy.version) entry.stale = true;
  if (!policyIsChanged(entry)) entry.stale = false;
  updatePolicyControls(entry);
}
async function applyPolicy(entry) {
  if (
    entry.saving ||
    !entry.current.enabled ||
    !policyIsChanged(entry) ||
    entry.stale ||
    entry.forceReview
  )
    return;
  const epoch = connectionEpoch;
  const id = entry.current.id;
  const mode = entry.draftMode;
  const expectedVersion = entry.expectedVersion;
  entry.saving = true;
  entry.messageText = '';
  updatePolicyControls(entry);
  try {
    const updated = await api(`/admin/policies/${encodeURIComponent(id)}/mode`, 'POST', {
      mode,
      expected_version: expectedVersion,
    });
    if (epoch !== connectionEpoch || policyStates.get(id) !== entry) return;
    if (
      !validPolicy(updated) ||
      updated.id !== id ||
      updated.mode !== mode ||
      updated.version !== expectedVersion + 1
    )
      throw new Error('Invalid policy response');
    acceptPolicy(entry, updated);
    entry.draftMode = undefined;
    entry.expectedVersion = undefined;
    entry.stale = false;
    entry.forceReview = false;
    entry.messageText = '';
    // The POST response is authoritative; an overview fetch failure cannot make it unapplied.
    try {
      await refresh();
    } catch (error) {
      if (epoch === connectionEpoch) showError(error);
    }
  } catch (error) {
    if (epoch !== connectionEpoch || policyStates.get(id) !== entry) return;
    entry.forceReview = true;
    let refreshed = false;
    try {
      await refresh();
      refreshed = true;
    } catch {
      /* Keep the last confirmed server state. */
    }
    if (epoch !== connectionEpoch || policyStates.get(id) !== entry) return;
    if (
      refreshed &&
      error.code !== 'SECURITY_STATE_UNPERSISTED' &&
      entry.current.mode === mode &&
      entry.current.version > expectedVersion &&
      entry.draftMode === undefined
    ) {
      // A fresh overview confirms the desired state, without proving this POST succeeded.
      entry.forceReview = false;
      entry.messageText = '';
    } else {
      entry.messageText =
        error.code === 'SECURITY_STATE_UNPERSISTED'
          ? 'Save not confirmed: security state could not be persisted. Check the broker before retrying.'
          : error.code === 'POLICY_DENIED' || error.code === 'INVALID_STATE'
            ? 'Save not confirmed. The policy changed or the action was denied. Review the current mode before retrying.'
            : 'Save not confirmed. Your draft is preserved. Review the current mode before retrying.';
    }
  } finally {
    if (epoch === connectionEpoch && policyStates.get(id) === entry) {
      entry.saving = false;
      updatePolicyControls(entry);
    }
  }
}
function createPolicy(policy) {
  const item = text('section', '', 'policy-control');
  const heading = text('div', '', 'section-heading mode-heading');
  const currentLabel = text('span', '', 'current-mode');
  heading.append(text('h2', 'Approval mode'), currentLabel);
  const choices = text('div', '', 'mode-choices');
  choices.setAttribute('role', 'radiogroup');
  choices.setAttribute('aria-label', 'Approval mode');
  const entry = {
    current: { ...policy },
    item,
    currentLabel,
    inputs: new Map(),
    draftMode: undefined,
    expectedVersion: undefined,
    stale: false,
    forceReview: false,
    saving: false,
    messageText: '',
  };
  for (const [mode, [name]] of Object.entries(modeCopy)) {
    const label = text('label', '', 'mode-choice');
    const input = document.createElement('input');
    input.type = 'radio';
    input.name = `mode-${policy.id}`;
    input.value = mode;
    input.onchange = () => {
      if (entry.saving || !input.checked) return;
      if (mode === entry.current.mode) {
        entry.draftMode = undefined;
        entry.expectedVersion = undefined;
        entry.stale = false;
        entry.forceReview = false;
      } else {
        if (entry.draftMode === undefined || !policyIsChanged(entry)) {
          entry.expectedVersion = entry.current.version;
          entry.stale = false;
          entry.forceReview = false;
        }
        entry.draftMode = mode;
      }
      entry.messageText = '';
      updatePolicyControls(entry);
    };
    label.append(input, text('span', name));
    entry.inputs.set(mode, input);
    choices.append(label);
  }
  entry.description = text('p', '', 'mode-description');
  entry.autoNotice = text('p', '', 'auto-notice');
  entry.review = text('div', '', 'mode-review');
  entry.reviewTitle = text('strong', '', 'review-title');
  const actions = text('div', '', 'mode-actions');
  entry.apply = text('button', 'Apply change');
  entry.apply.onclick = () => void applyPolicy(entry);
  entry.reviewLatest = text('button', 'Review latest', 'secondary');
  entry.reviewLatest.onclick = () => {
    if (entry.saving) return;
    entry.expectedVersion = entry.current.version;
    entry.stale = false;
    entry.forceReview = false;
    entry.messageText = '';
    updatePolicyControls(entry);
  };
  entry.cancel = text('button', 'Cancel edit', 'quiet');
  entry.cancel.onclick = () => {
    if (entry.saving) return;
    entry.draftMode = undefined;
    entry.expectedVersion = undefined;
    entry.stale = false;
    entry.forceReview = false;
    entry.messageText = '';
    updatePolicyControls(entry);
  };
  actions.append(entry.reviewLatest, entry.apply, entry.cancel);
  entry.review.append(
    entry.reviewTitle,
    text('p', 'Pending requests will be cancelled and existing sessions ended.', 'review-impact'),
    actions,
  );
  entry.message = text('p', '', 'mode-message');
  entry.message.setAttribute('role', 'status');
  entry.message.setAttribute('aria-live', 'polite');
  const details = disclosure('Policy details', `policy:${policy.id}`);
  entry.metadata = text('p', '', 'detail-value mono');
  details.append(entry.metadata);
  item.append(
    heading,
    choices,
    entry.description,
    entry.autoNotice,
    entry.review,
    entry.message,
    details,
  );
  updatePolicyControls(entry);
  return entry;
}
function syncPolicies(policies) {
  if (policies.length && policyStates.size === 0) $('policies').replaceChildren();
  const present = new Set();
  for (const policy of policies) {
    if (!validPolicy(policy)) throw new Error('Invalid policy response');
    present.add(policy.id);
    let entry = policyStates.get(policy.id);
    if (!entry) {
      entry = createPolicy(policy);
      policyStates.set(policy.id, entry);
      $('policies').append(entry.item);
    } else acceptPolicy(entry, policy);
  }
  for (const [id, entry] of policyStates) {
    if (present.has(id)) continue;
    entry.item.remove();
    policyStates.delete(id);
  }
  if (!policies.length && !$('policies').children.length)
    $('policies').append(text('p', 'No approval policy is configured.', 'hint'));
}
function destinationLabel(destination) {
  try {
    return new URL(destination).host;
  } catch {
    return destination;
  }
}
function requestItem(request, compact = false) {
  const item = text('article', '', compact ? 'activity-item' : 'request-item');
  const heading = text('div', '', 'request-heading');
  const identity = text('div', '', 'request-identity');
  identity.append(
    text('strong', destinationLabel(request.destination)),
    text(
      'span',
      `${request.account_display_name} · ${request.client_display_name}`,
      'request-subtitle',
    ),
  );
  heading.append(
    identity,
    text(
      'span',
      Object.hasOwn(stateLabels, request.state) ? stateLabels[request.state] : 'Unknown state',
      `state state-${request.state.toLowerCase()}`,
    ),
  );
  item.append(heading);
  if (!compact) {
    item.append(text('p', `Requested access: ${request.session_action_profile}`, 'request-access'));
    if (request.state === 'AWAITING_APPROVAL') {
      const next = text('div', '', 'request-next');
      next.append(text('span', 'Review and approve in Broker Approval on your iPhone.'));
      next.append(
        action(
          'Deny',
          () => api(`/admin/requests/${encodeURIComponent(request.request_id)}/deny`, 'POST'),
          'quiet danger',
        ),
      );
      item.append(next);
    } else if (request.state === 'OUTCOME_UNKNOWN') {
      item.append(
        text('p', 'The result is uncertain. Do not retry this request.', 'hint attention'),
      );
    } else if (request.state === 'INTERACTION_REQUIRED') {
      item.append(
        text(
          'p',
          'The broker needs owner attention before this flow can continue.',
          'hint attention',
        ),
      );
    }
  }
  const details = disclosure('Request details', `request:${request.request_id}`);
  details.append(
    text('p', `Destination: ${request.destination}`, 'detail-value'),
    text('p', `Agent-stated purpose: ${request.purpose}`, 'detail-value'),
    text('p', `Access: ${request.session_action_profile}`, 'detail-value'),
    text('p', `Request: ${request.request_id}`, 'detail-value mono'),
  );
  item.append(details);
  return item;
}
function fingerprint(device) {
  const box = text('div', '', 'fingerprint');
  box.append(text('span', 'Approval key · SHA-256', 'hint'), text('code', device.key_fingerprint));
  return box;
}
function pendingDevice(device) {
  const item = text('article', '', 'pending-device');
  item.append(text('strong', device.name), fingerprint(device));
  const verificationKey = `${device.id}:${device.key_fingerprint}`;
  const label = text('label', '', 'verification-check');
  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox';
  checkbox.checked = verifiedFingerprints.has(verificationKey);
  label.append(
    checkbox,
    text('span', 'This full fingerprint matches the approval key shown on my iPhone.'),
  );
  const confirm = action(
    'Confirm device',
    async () => {
      if (!checkbox.checked) return;
      await api(`/admin/devices/${encodeURIComponent(device.id)}/confirm`, 'POST');
      verifiedFingerprints.delete(verificationKey);
    },
    'primary',
  );
  confirm.disabled = !checkbox.checked;
  checkbox.onchange = () => {
    if (checkbox.checked) verifiedFingerprints.add(verificationKey);
    else verifiedFingerprints.delete(verificationKey);
    confirm.disabled = !checkbox.checked;
  };
  const buttons = text('div', '', 'row');
  buttons.append(
    confirm,
    action(
      'Remove device',
      () => api(`/admin/devices/${encodeURIComponent(device.id)}/revoke`, 'POST'),
      'quiet danger',
    ),
  );
  item.append(label, buttons);
  return item;
}
function deviceItem(device) {
  const item = text('article', '', 'device-item');
  const heading = text('div', '', 'section-heading');
  const identity = text('div', '', 'device-identity');
  identity.append(
    text('strong', device.name),
    text('span', device.status === 'ACTIVE' ? 'Owner-confirmed' : 'Revoked', 'hint'),
  );
  heading.append(identity);
  item.append(heading);
  const details = disclosure('Device details', `device:${device.id}`);
  details.append(fingerprint(device));
  if (device.status !== 'REVOKED')
    details.append(
      action(
        'Revoke device',
        () => api(`/admin/devices/${encodeURIComponent(device.id)}/revoke`, 'POST'),
        'quiet danger',
      ),
    );
  item.append(details);
  return item;
}
function clearPairing() {
  pairingExpiresAt = 0;
  pairingDeviceIds.clear();
  $('pairing-code').value = '';
  $('pairing-code').type = 'password';
  $('reveal-pairing').textContent = 'Show';
  $('reveal-pairing').setAttribute('aria-pressed', 'false');
  $('pairing').hidden = true;
}
function render(data) {
  const openDetails = new Set(
    Array.from(
      document.querySelectorAll('[data-detail-key][open]'),
      (element) => element.dataset.detailKey,
    ),
  );
  const pending = data.devices.filter((device) => device.status === 'PENDING_CONFIRMATION');
  const active = data.devices.filter((device) => device.status === 'ACTIVE');
  lastDevices = data.devices;
  if (pairingExpiresAt && pending.some((device) => !pairingDeviceIds.has(device.id)))
    clearPairing();

  connectionStatus(data.devices);
  const pendingKeys = new Set(pending.map((device) => `${device.id}:${device.key_fingerprint}`));
  for (const key of verifiedFingerprints) {
    if (!pendingKeys.has(key)) verifiedFingerprints.delete(key);
  }
  $('setup').hidden = Boolean(active.length && !pending.length);
  $('setup-title').textContent = pending.length ? 'Confirm your iPhone' : 'Pair your iPhone';
  $('setup-description').textContent = pending.length
    ? 'Compare the complete fingerprint with “Approval key SHA-256” in Broker Approval before confirming.'
    : 'Your iPhone reviews each request and signs your approval.';
  $('setup-pair').hidden = Boolean(pending.length);
  $('pending-devices').replaceChildren(...pending.map(pendingDevice));

  const current = data.requests.filter((request) => !completedStates.has(request.state));
  current.sort(
    (a, b) => Number(b.state === 'AWAITING_APPROVAL') - Number(a.state === 'AWAITING_APPROVAL'),
  );
  $('requests').replaceChildren(...current.map((request) => requestItem(request)));
  if (!current.length) {
    const empty = text('div', '', 'empty-state');
    empty.append(
      text('p', 'No pending requests.', 'empty-title'),
      text(
        'p',
        active.length
          ? 'New login requests appear here.'
          : 'Pair your iPhone to start receiving approval requests.',
      ),
    );
    $('requests').append(empty);
  }
  const recent = data.requests.filter((request) => completedStates.has(request.state));
  $('history-count').textContent = String(recent.length);
  $('history').hidden = !recent.length;
  $('recent-requests').replaceChildren(...recent.map((request) => requestItem(request, true)));

  $('settings-summary').textContent =
    `${active.length} ${active.length === 1 ? 'device' : 'devices'}`;
  const otherDevices = data.devices.filter((device) => device.status !== 'PENDING_CONFIRMATION');
  $('devices').replaceChildren(...otherDevices.map(deviceItem));
  if (!otherDevices.length)
    $('devices').append(
      text(
        'p',
        pending.length
          ? 'Your iPhone is awaiting confirmation above.'
          : 'No owner-confirmed device yet.',
        'hint',
      ),
    );
  syncPolicies(data.policies);
  for (const details of document.querySelectorAll('[data-detail-key]'))
    details.open = openDetails.has(details.dataset.detailKey);
}
async function refresh() {
  const epoch = connectionEpoch;
  const data = await api('/admin/overview');
  if (epoch !== connectionEpoch || !ownerToken) return;
  const snapshot = JSON.stringify(data);
  if (snapshot !== overviewSnapshot) {
    render(data);
    overviewSnapshot = snapshot;
  }
  connectionStatus(data.devices);
  if (noticeKind === 'error') notice('');
}
async function startPairing() {
  const epoch = connectionEpoch;
  $('pair').disabled = true;
  $('setup-pair').disabled = true;
  try {
    const data = await api('/admin/pairings', 'POST');
    if (epoch !== connectionEpoch || !ownerToken) return;
    pairingExpiresAt = Date.parse(data.expires_at);
    pairingDeviceIds = new Set(lastDevices.map((device) => device.id));
    $('pairing-code').value = data.pairing_code;
    $('pairing-code').type = 'password';
    $('reveal-pairing').textContent = 'Show';
    $('reveal-pairing').setAttribute('aria-pressed', 'false');
    $('pairing-expiry').textContent =
      `Expires at ${new Date(data.expires_at).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}. Keep this code private.`;
    $('pairing').hidden = false;
    notice('');
    $('pairing').scrollIntoView({ behavior: 'smooth', block: 'center' });
  } catch (error) {
    if (epoch === connectionEpoch) showError(error);
  } finally {
    $('pair').disabled = false;
    $('setup-pair').disabled = false;
  }
}
$('connect-form').onsubmit = async (event) => {
  event.preventDefault();
  connectionEpoch++;
  const epoch = connectionEpoch;
  ownerToken = $('token').value;
  $('token').value = '';
  $('connect-button').disabled = true;
  try {
    await refresh();
    if (epoch !== connectionEpoch) return;
    $('dashboard').hidden = false;
    $('connect').hidden = true;
    $('disconnect').hidden = false;
    $('connection-status').hidden = false;
    notice('');
  } catch (error) {
    if (epoch === connectionEpoch) {
      ownerToken = '';
      showError(error);
    }
  } finally {
    $('connect-button').disabled = false;
  }
};
$('disconnect').onclick = () => {
  connectionEpoch++;
  ownerToken = '';
  overviewSnapshot = '';
  lastDevices = [];
  verifiedFingerprints.clear();
  policyStates.clear();
  clearPairing();
  $('dashboard').hidden = true;
  $('requests').replaceChildren();
  $('devices').replaceChildren();
  $('pending-devices').replaceChildren();
  $('recent-requests').replaceChildren();
  $('policies').replaceChildren();
  $('connect').hidden = false;
  $('disconnect').hidden = true;
  $('connection-status').hidden = true;
  notice('');
  $('token').focus();
};
$('pair').onclick = startPairing;
$('setup-pair').onclick = startPairing;
$('hide-pairing').onclick = clearPairing;
$('reveal-pairing').onclick = () => {
  const reveal = $('pairing-code').type === 'password';
  $('pairing-code').type = reveal ? 'text' : 'password';
  $('reveal-pairing').textContent = reveal ? 'Hide' : 'Show';
  $('reveal-pairing').setAttribute('aria-pressed', String(reveal));
};
$('copy-pairing').onclick = async () => {
  if (pairingExpiresAt <= Date.now()) {
    clearPairing();
    notice('The pairing code expired. Start pairing again.');
    return;
  }
  try {
    await navigator.clipboard.writeText($('pairing-code').value);
    notice('Pairing code copied. Paste it in Broker Approval on your iPhone.');
  } catch {
    notice('Copy is unavailable. Use Show to enter the code privately in the iPhone app.');
  }
};
setInterval(() => {
  if (pairingExpiresAt && pairingExpiresAt <= Date.now()) clearPairing();
  if (ownerToken && document.visibilityState === 'visible') {
    const epoch = connectionEpoch;
    void refresh().catch((error) => {
      if (epoch !== connectionEpoch || !ownerToken) return;
      $('connection-status').textContent = 'Reconnecting';
      $('connection-status').classList.remove('ready');
      showError(error);
    });
  }
}, 2000);
