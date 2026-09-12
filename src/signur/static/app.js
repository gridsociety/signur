const stateLabels = {
  to_sign: "Da firmare",
  signing_failed: "Firma fallita",
  signed: "Firmato",
};
const jobLabels = {
  queued: ["Tentativo in coda", "La firma verrà avviata appena possibile."],
  running: ["Firma in corso", "Il documento è in elaborazione."],
  completed: ["Firma completata", "Il risultato è pronto per il download."],
  failed: ["Firma fallita", "Puoi correggere la configurazione e riprovare."],
};
const roleLabels = {
  no_access: "Nessun accesso",
  user: "Utente",
  admin: "Amministratore",
};
const signatureModeLabels = {
  graphic: "Grafica",
  cades: "CAdES",
  pades: "PAdES",
  xades: "XAdES",
};

let signerIdentity = null;
let signingProxies = [];
let graphicSignatures = [];
let currentProfile = null;
let allUsers = [];
let canTransferOwnership = false;
let signingDocument = null;
let ownerDocument = null;
let placements = [];
let selectedPlacementId = null;
// Handles for the placements in this page only: they never reach the server, and
// crypto.randomUUID is unavailable outside a secure context, such as a plain HTTP
// address on the local network.
let placementCounter = 0;
let pdfPreviewPromise = null;
let pdfPreviewToken = 0;
let activeJobId = null;
let jobPollTimer = null;
let eventSocket = null;
let reconnectTimer = null;
let realtimeFingerprint = "";
let discoveredLocalCertificates = [];
let adminProxies = [];
let adminGraphics = [];
let localDiscoveryToken = 0;
let localLibraryDebounceTimer = null;
const activeDocumentJobs = new Map();
const PER_PAGE = 20;
const documentFilters = { search: "", owners: [], offset: 0 };
const userFilters = { search: "", offset: 0 };
const ownerOptions = { term: "", items: [], total: 0, loading: false, active: -1 };
let ownerOptionsToken = 0;

async function api(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const error = new Error(body.error?.message || "Operazione non riuscita.");
    error.code = body.error?.code;
    throw error;
  }
  if (response.status === 204) return null;
  return response.json();
}

// Typing is a stream of keystrokes and each one would be a request, so the
// listings only follow the last one of a burst.
function debounce(action, delay = 250) {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => action(...args), delay);
  };
}

// 1 … 4 5 6 … 20: the current page keeps its neighbours, both ends stay one
// click away, and what is skipped in between is written as a gap.
function pageNumbers(current, last) {
  const wanted = new Set([1, last, current - 1, current, current + 1]);
  if (current <= 3) [2, 3, 4].forEach((page) => wanted.add(page));
  if (current >= last - 2) [last - 1, last - 2, last - 3].forEach((page) => wanted.add(page));
  const pages = [...wanted].filter((page) => page >= 1 && page <= last).sort((a, b) => a - b);
  return pages.flatMap((page, index) => (index && page - pages[index - 1] > 1 ? ["…", page] : [page]));
}

function renderPager(container, { total, limit, offset, go }) {
  container.replaceChildren();
  const last = Math.max(1, Math.ceil(total / limit));
  if (last === 1) return;
  const current = Math.min(last, Math.floor(offset / limit) + 1);
  const arrow = (symbol, target, description) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "button page";
    button.textContent = symbol;
    button.setAttribute("aria-label", description);
    button.disabled = target < 1 || target > last;
    button.addEventListener("click", () => go((target - 1) * limit));
    return button;
  };
  container.append(arrow("‹", current - 1, "Pagina precedente"));
  for (const page of pageNumbers(current, last)) {
    if (page === "…") {
      const gap = document.createElement("span");
      gap.className = "page-gap";
      gap.textContent = "…";
      gap.setAttribute("aria-hidden", "true");
      container.append(gap);
      continue;
    }
    const button = document.createElement("button");
    button.type = "button";
    button.className = "button page";
    button.textContent = String(page);
    button.setAttribute("aria-label", `Pagina ${page}`);
    if (page === current) {
      button.classList.add("current");
      button.setAttribute("aria-current", "page");
    }
    button.addEventListener("click", () => go((page - 1) * limit));
    container.append(button);
  }
  container.append(arrow("›", current + 1, "Pagina successiva"));
}

function showNotice(message, kind = "success") {
  const notice = document.querySelector("#notice");
  notice.textContent = message;
  notice.className = `notice ${kind}`;
  notice.hidden = false;
}

function formatDate(value) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("it-IT", { dateStyle: "medium" }).format(new Date(value));
}

function formatDateTime(value) {
  if (!value) return "Mai";
  return new Intl.DateTimeFormat("it-IT", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function renderDocuments(items) {
  const container = document.querySelector("#documents");
  container.replaceChildren();
  if (!items.length) {
    const filtering = Boolean(documentFilters.search || documentFilters.owners.length);
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = filtering
      ? "Nessun documento corrisponde alla ricerca."
      : "Non ci sono ancora documenti.";
    container.append(empty);
    return;
  }

  for (const item of items) {
    const row = document.createElement("article");
    row.className = "document";
    const description = document.createElement("div");
    const name = document.createElement("div");
    name.className = "document-name";
    name.textContent = item.original_name;
    const meta = document.createElement("div");
    meta.className = "document-meta";
    const metaParts = [
      formatDate(item.created_at),
      `${Math.ceil(item.size_bytes / 1024)} KB`,
      `Proprietario: ${item.owner.display_name}`,
    ];
    if (item.signature_mode) metaParts.push(`Firma: ${signatureModeLabels[item.signature_mode] || item.signature_mode}`);
    const signed = item.state === "signed";
    if (signed) {
      const shorthand = pdfaShorthand(item);
      if (shorthand) metaParts.push(shorthand);
    }
    meta.textContent = metaParts.join(" · ");
    description.append(name, meta);
    // The full warning is there to inform a decision, so only while one is pending.
    const pdfaNote = signed ? null : pdfaWarning(item);
    if (pdfaNote) description.append(pdfaNote);

    const activeJob = activeDocumentJobs.get(item.id);
    const status = document.createElement("span");
    status.className = `state ${item.state}`;
    status.textContent = activeJob ? (activeJob.status === "queued" ? "In coda" : "Firma in corso") : (stateLabels[item.state] || item.state);

    const actions = document.createElement("div");
    actions.className = "document-actions";
    const original = document.createElement("a");
    original.className = "button";
    original.textContent = "Originale";
    original.href = `/api/v1/documents/${item.id}/original`;
    actions.append(original);

    if (item.state === "signed") {
      const result = document.createElement("a");
      result.className = "button primary";
      result.textContent = "Scarica firmato";
      result.href = `/api/v1/documents/${item.id}/result`;
      actions.append(result);
    } else {
      const sign = document.createElement("button");
      sign.className = "button primary";
      sign.textContent = activeJob ? "Firma in corso" : (item.state === "signing_failed" ? "Riprova" : "Firma");
      const hasDigital = ["cades", "pades", "xades"].some((mode) => item.capabilities.includes(mode)) && (
        availableSigningProxies().length > 0 || Boolean(signerIdentity)
      );
      const hasGraphic = item.capabilities.includes("graphic") && graphicSignatures.length > 0;
      sign.disabled = Boolean(activeJob) || (!hasDigital && !hasGraphic);
      sign.addEventListener("click", () => openSignDialog(item));
      actions.append(sign);
      const remove = document.createElement("button");
      remove.className = "button danger";
      remove.textContent = "Elimina";
      remove.disabled = Boolean(activeJob);
      remove.addEventListener("click", () => deleteDocument(item));
      actions.append(remove);
    }
    if (canTransferOwnership) {
      const transfer = document.createElement("button");
      transfer.className = "button";
      transfer.textContent = "Cambia proprietario";
      transfer.disabled = Boolean(activeJob);
      transfer.addEventListener("click", () => openOwnerDialog(item));
      actions.append(transfer);
    }
    row.append(description, status, actions);
    container.append(row);
  }
}

async function loadDocuments() {
  const params = new URLSearchParams({ limit: PER_PAGE, offset: documentFilters.offset });
  if (documentFilters.search) params.set("search", documentFilters.search);
  for (const owner of documentFilters.owners) params.append("owner", owner.id);
  const listing = await api(`/api/v1/documents?${params}`);
  // Deleting the last document of a page, or narrowing the search, would
  // otherwise leave the reader looking at an empty page with content behind it.
  if (!listing.items.length && listing.total && documentFilters.offset >= listing.total) {
    documentFilters.offset = (Math.ceil(listing.total / PER_PAGE) - 1) * PER_PAGE;
    await loadDocuments();
    return;
  }
  renderDocuments(listing.items);
  renderPager(document.querySelector("#documents-pager"), {
    total: listing.total,
    limit: PER_PAGE,
    offset: listing.offset,
    go: (offset) => {
      documentFilters.offset = offset;
      refreshDocuments();
    },
  });
}

function refreshDocuments() {
  loadDocuments().catch((error) => showNotice(error.message, "error"));
}

async function deleteDocument(item) {
  if (!window.confirm(`Eliminare definitivamente “${item.original_name}”?`)) return;
  try {
    await api(`/api/v1/documents/${item.id}`, { method: "DELETE" });
    showNotice("Documento eliminato.");
    await loadDocuments();
  } catch (error) {
    showNotice(error.message, "error");
  }
}

// Only an administrator sees documents that are not their own, so only an
// administrator is offered the filter that picks whose.
function ownerCandidateQuery(extra) {
  const params = new URLSearchParams({ limit: extra.limit, offset: extra.offset ?? 0 });
  if (extra.search) params.set("search", extra.search);
  for (const role of ["user", "admin"]) params.append("role", role);
  return params;
}

function renderOwnerChips() {
  const chips = document.querySelector("#owner-chips");
  chips.replaceChildren();
  for (const owner of documentFilters.owners) {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.append(owner.display_name);
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "chip-remove";
    remove.textContent = "×";
    remove.setAttribute("aria-label", `Togli ${owner.display_name} dal filtro`);
    remove.addEventListener("click", () => toggleOwnerFilter(owner));
    chip.append(remove);
    chips.append(chip);
  }
  document.querySelector("#owner-clear").hidden = documentFilters.owners.length === 0;
  document.querySelector("#owner-search").placeholder = documentFilters.owners.length ? "" : "Tutti";
}

function renderOwnerOptions() {
  const list = document.querySelector("#owner-options");
  const input = document.querySelector("#owner-search");
  list.replaceChildren();
  if (!ownerOptions.items.length) {
    const empty = document.createElement("li");
    empty.className = "combobox-note";
    empty.textContent = ownerOptions.loading ? "Ricerca in corso…" : "Nessun utente trovato.";
    list.append(empty);
    input.removeAttribute("aria-activedescendant");
    return;
  }
  ownerOptions.items.forEach((user, index) => {
    const option = document.createElement("li");
    option.className = "combobox-option";
    option.id = `owner-option-${index}`;
    option.setAttribute("role", "option");
    const chosen = documentFilters.owners.some((owner) => owner.id === user.id);
    option.setAttribute("aria-selected", String(chosen));
    option.classList.toggle("chosen", chosen);
    option.classList.toggle("active", index === ownerOptions.active);
    const name = document.createElement("strong");
    name.textContent = user.display_name;
    const detail = document.createElement("span");
    detail.className = "muted";
    detail.textContent = user.email || user.username;
    option.append(name, detail);
    // Choosing with the mouse must not take the focus away from the box, or it
    // would close before the click lands.
    option.addEventListener("mousedown", (event) => {
      event.preventDefault();
      toggleOwnerFilter(user);
    });
    list.append(option);
  });
  if (ownerOptions.loading || ownerOptions.items.length < ownerOptions.total) {
    const more = document.createElement("li");
    more.className = "combobox-note";
    more.textContent = "Altri utenti in arrivo…";
    list.append(more);
  }
  const active = ownerOptions.active >= 0 ? `owner-option-${ownerOptions.active}` : null;
  if (active) input.setAttribute("aria-activedescendant", active);
  else input.removeAttribute("aria-activedescendant");
}

async function loadOwnerOptions({ append = false } = {}) {
  if (append && (ownerOptions.loading || ownerOptions.items.length >= ownerOptions.total)) return;
  const token = ++ownerOptionsToken;
  ownerOptions.loading = true;
  const offset = append ? ownerOptions.items.length : 0;
  try {
    const listing = await api(
      `/api/v1/admin/users?${ownerCandidateQuery({ limit: PER_PAGE, offset, search: ownerOptions.term })}`,
    );
    // A slower answer to an older search must not replace the newer one.
    if (token !== ownerOptionsToken) return;
    ownerOptions.items = append ? [...ownerOptions.items, ...listing.items] : listing.items;
    ownerOptions.total = listing.total;
  } catch (error) {
    if (token === ownerOptionsToken) showNotice(error.message, "error");
  } finally {
    if (token === ownerOptionsToken) {
      ownerOptions.loading = false;
      renderOwnerOptions();
    }
  }
}

function openOwnerOptions() {
  const list = document.querySelector("#owner-options");
  if (!list.hidden) return;
  list.hidden = false;
  document.querySelector("#owner-search").setAttribute("aria-expanded", "true");
  renderOwnerOptions();
  loadOwnerOptions();
}

function closeOwnerOptions() {
  ownerOptions.active = -1;
  document.querySelector("#owner-options").hidden = true;
  document.querySelector("#owner-search").setAttribute("aria-expanded", "false");
}

function moveOwnerHighlight(step) {
  if (!ownerOptions.items.length) return;
  const last = ownerOptions.items.length - 1;
  const next = ownerOptions.active + step;
  ownerOptions.active = next < 0 ? last : next > last ? 0 : next;
  renderOwnerOptions();
  document.querySelector(`#owner-option-${ownerOptions.active}`)?.scrollIntoView({ block: "nearest" });
}

function toggleOwnerFilter(user) {
  const chosen = documentFilters.owners.findIndex((owner) => owner.id === user.id);
  if (chosen >= 0) documentFilters.owners.splice(chosen, 1);
  else documentFilters.owners.push({ id: user.id, display_name: user.display_name });
  documentFilters.offset = 0;
  renderOwnerChips();
  renderOwnerOptions();
  refreshDocuments();
}

function clearOwnerFilter() {
  if (!documentFilters.owners.length) return;
  documentFilters.owners = [];
  documentFilters.offset = 0;
  renderOwnerChips();
  renderOwnerOptions();
  refreshDocuments();
}

// The button that hands a document to somebody else is only worth showing when
// there is somebody else: two candidates are enough to know.
async function refreshOwnershipTools() {
  const filter = document.querySelector("#owner-filter");
  if (currentProfile?.role !== "admin") {
    canTransferOwnership = false;
    filter.hidden = true;
    return;
  }
  filter.hidden = false;
  try {
    const listing = await api(`/api/v1/admin/users?${ownerCandidateQuery({ limit: 2 })}`);
    canTransferOwnership = listing.items.some((user) => user.id !== currentProfile.id);
  } catch {
    canTransferOwnership = false;
  }
}

function renderUsers() {
  const container = document.querySelector("#users");
  container.replaceChildren();
  if (!allUsers.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = userFilters.search ? "Nessun utente corrisponde alla ricerca." : "Nessun utente.";
    container.append(empty);
    return;
  }
  for (const user of allUsers) {
    const row = document.createElement("article");
    row.className = "user-row";
    const identity = document.createElement("div");
    const name = document.createElement("strong");
    name.textContent = user.display_name;
    const details = document.createElement("span");
    details.className = "user-meta";
    details.textContent = `${user.username} · ${user.email || "Nessuna email"} · Ultimo accesso ${formatDateTime(user.last_seen_at)}`;
    identity.append(name, details);

    const controls = document.createElement("div");
    controls.className = "role-controls";
    const select = document.createElement("select");
    select.setAttribute("aria-label", `Ruolo di ${user.display_name}`);
    for (const role of ["no_access", "user", "admin"]) {
      const option = document.createElement("option");
      option.value = role;
      option.textContent = roleLabels[role];
      option.selected = role === user.role;
      select.append(option);
    }
    const save = document.createElement("button");
    save.className = "button";
    save.textContent = "Salva ruolo";
    const isSelf = user.id === currentProfile.id;
    select.disabled = isSelf;
    save.disabled = isSelf;
    if (isSelf) save.title = "Il proprio ruolo amministratore non può essere modificato qui.";
    select.addEventListener("change", () => { save.disabled = select.value === user.role; });
    save.addEventListener("click", () => saveUserRole(user, select, save));
    controls.append(select, save);
    if (authMode === "local") {
      const edit = document.createElement("button");
      edit.className = "button";
      edit.textContent = "Modifica";
      edit.addEventListener("click", () => openUserDialog(user));
      controls.append(edit);
    }
    row.append(identity, controls);
    container.append(row);
  }
}

async function loadUsers() {
  const params = new URLSearchParams({ limit: PER_PAGE, offset: userFilters.offset });
  if (userFilters.search) params.set("search", userFilters.search);
  const listing = await api(`/api/v1/admin/users?${params}`);
  if (!listing.items.length && listing.total && userFilters.offset >= listing.total) {
    userFilters.offset = (Math.ceil(listing.total / PER_PAGE) - 1) * PER_PAGE;
    await loadUsers();
    return;
  }
  allUsers = listing.items;
  renderUsers();
  renderPager(document.querySelector("#users-pager"), {
    total: listing.total,
    limit: PER_PAGE,
    offset: listing.offset,
    go: (offset) => {
      userFilters.offset = offset;
      refreshUsers();
    },
  });
}

function refreshUsers() {
  loadUsers().catch((error) => showNotice(error.message, "error"));
}

async function saveUserRole(user, select, button) {
  button.disabled = true;
  try {
    await api(`/api/v1/admin/users/${user.id}/role`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role: select.value }),
    });
    showNotice(`Ruolo di ${user.display_name} aggiornato.`);
    await loadUsers();
    // Revoking the last other account takes the transfer button away with it.
    await refreshOwnershipTools();
    refreshDocuments();
  } catch (error) {
    showNotice(error.message, "error");
    select.value = user.role;
    button.disabled = false;
  }
}

function showSigner(identity) {
  signerIdentity = identity;
  const card = document.querySelector("#signer");
  card.classList.remove("unavailable");
  document.querySelector("#signer-name").textContent = identity.display_name;
  document.querySelector("#signer-subject").textContent = identity.subject;
  document.querySelector("#signer-issuer").textContent = identity.issuer;
  document.querySelector("#signer-serial").textContent = identity.serial_number;
  document.querySelector("#signer-validity").textContent = `${formatDate(identity.not_valid_before)} – ${formatDate(identity.not_valid_after)}`;
  document.querySelector("#signer-details").hidden = false;
}

async function loadSigningResources() {
  const [proxiesResult, graphicsResult] = await Promise.allSettled([
    api("/api/v1/signing-proxies"),
    api("/api/v1/graphic-signatures"),
  ]);
  signingProxies = proxiesResult.status === "fulfilled" ? proxiesResult.value.items : [];
  graphicSignatures = graphicsResult.status === "fulfilled" ? graphicsResult.value.items : [];

  let identity = signingProxies.find((proxy) => proxy.available && proxy.identity)?.identity;
  if (!identity) {
    // Nothing is configured here, so ask the single proxy declared in the
    // environment. Asking it when certificates exist only produces a failed
    // request, since that endpoint ignores them.
    const [legacy] = await Promise.allSettled([api("/api/v1/signing-identity")]);
    if (legacy.status === "fulfilled") identity = legacy.value;
  }
  if (identity) {
    showSigner(identity);
    return;
  }
  signerIdentity = null;
  document.querySelector("#signer").classList.add("unavailable");
  document.querySelector("#signer-name").textContent = "Certificato non disponibile";
}

function currentGraphicVersion(graphic) {
  return graphic?.versions.find((version) => version.version_number === graphic.current_version_number);
}

function pdfaShorthand(item) {
  // Once the document is signed the warning has served its purpose: what is left
  // is a fact about the file, and it belongs with the other small print.
  if (!item || item.pdfa_status === "not_applicable" || item.pdfa_status === "conformant") return null;
  return item.pdfa_status === "indeterminate" ? "PDF/A non verificato" : "non PDF/A";
}

function pdfaWarning(item) {
  // Never say anything about PDF/A for a file that is not a PDF.
  if (!item || item.pdfa_status === "not_applicable" || item.pdfa_status === "conformant") return null;
  const inside = item.input_format === "cms_attached";
  const subject = inside ? "Il PDF contenuto nel P7M" : "Il PDF";
  const note = document.createElement("p");
  if (item.pdfa_status === "indeterminate") {
    note.className = "pdfa-note failed";
    note.textContent = `Verifica non riuscita. Non è stato possibile verificare la conformità PDF/A ${inside ? "del PDF contenuto nel P7M" : "del PDF"}. L'immutabilità della sua rappresentazione nel tempo non è garantita. Puoi comunque procedere con la firma.`;
    return note;
  }
  note.className = "pdfa-note";
  note.textContent = `${subject} non è conforme a PDF/A: non è garantita l'immutabilità della sua rappresentazione nel tempo. Puoi comunque procedere con la firma.`;
  return note;
}

function availableSigningProxies() {
  return signingProxies.filter((proxy) => proxy.available && proxy.identity);
}

function populateSignDialog(item) {
  const modeSelect = document.querySelector("#signature-mode");
  modeSelect.replaceChildren();
  const addMode = (value, label, enabled) => {
    if (!item.capabilities.includes(value)) return;
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    option.disabled = !enabled;
    modeSelect.append(option);
  };
  const certificateReady = availableSigningProxies().length > 0 || Boolean(signerIdentity);
  addMode("cades", "CAdES — file .p7m", certificateReady);
  addMode("pades", "PAdES — PDF firmato", certificateReady);
  addMode("xades", "XAdES — XML firmato", certificateReady);
  addMode("graphic", "Firma grafica — PDF", graphicSignatures.length > 0);

  document.querySelector("#pades-graphic").checked = false;
  document.querySelector("#xades-packaging").value = "enveloped";

  const proxySelect = document.querySelector("#signing-proxy");
  proxySelect.replaceChildren();
  const availableProxies = availableSigningProxies();
  for (const proxy of availableProxies) {
    const option = document.createElement("option");
    option.value = proxy.id;
    option.textContent = `${proxy.name} — ${proxy.identity.display_name}`;
    proxySelect.append(option);
  }
  document.querySelector("#proxy-selector-field").hidden = availableProxies.length <= 1;

  const graphicSelect = document.querySelector("#graphic-signature");
  graphicSelect.replaceChildren();
  for (const graphic of graphicSignatures) {
    const version = currentGraphicVersion(graphic);
    if (!version) continue;
    const option = document.createElement("option");
    option.value = version.id;
    option.textContent = `${graphic.name} · versione ${version.version_number}`;
    graphicSelect.append(option);
  }

  const usable = [...modeSelect.options].find((option) => !option.disabled);
  if (usable) modeSelect.value = usable.value;
  document.querySelector("#confirm-sign").disabled = !usable;
  updateSignMode();
}

function openSignDialog(item) {
  signingDocument = item;
  activeJobId = null;
  placements = [];
  selectedPlacementId = null;
  clearTimeout(jobPollTimer);
  document.querySelector("#dialog-document").textContent = item.original_name;
  document.querySelector("#sign-config").hidden = false;
  document.querySelector("#sign-progress").hidden = true;
  document.querySelector("#download-result").hidden = true;
  const confirm = document.querySelector("#confirm-sign");
  confirm.hidden = false;
  confirm.textContent = "Conferma e firma";
  document.querySelector("#signing-pin").value = "";
  document.querySelector("#cades-strategy").value = "nested";
  const legacyP7m = item.input_format === "opaque" && item.original_name.toLowerCase().endsWith(".p7m");
  const hasPdfPreview = ["pdf", "cms_attached"].includes(item.input_format) || legacyP7m;
  document.querySelector("#sign-dialog").classList.toggle("compact", !hasPdfPreview);
  document.querySelector("#preview-column").hidden = !hasPdfPreview;
  document.querySelector("#embedded-pdf-label").hidden = item.input_format !== "cms_attached" && !legacyP7m;
  const previewUrl = `/api/v1/documents/${item.id}/preview`;
  document.querySelector("#preview-fallback").href = previewUrl;
  if (hasPdfPreview) {
    const previewToken = ++pdfPreviewToken;
    pdfPreviewPromise = import("/static/pdf-preview.js");
    pdfPreviewPromise.then((preview) => {
      if (previewToken === pdfPreviewToken) preview.openPdf(previewUrl);
    });
  }
  populateSignDialog(item);
  renderPlacements();
  document.querySelector("#sign-dialog").showModal();
}

function selectedProxyIdentity() {
  const availableProxies = availableSigningProxies();
  if (availableProxies.length === 1) return availableProxies[0].identity;
  const proxyId = document.querySelector("#signing-proxy").value;
  if (proxyId) return availableProxies.find((proxy) => proxy.id === proxyId)?.identity || null;
  return signerIdentity;
}

function selectedCertificateConfig() {
  const availableProxies = availableSigningProxies();
  if (availableProxies.length === 1) return availableProxies[0];
  const proxyId = document.querySelector("#signing-proxy").value;
  return availableProxies.find((proxy) => proxy.id === proxyId) || null;
}

function selectedProxyId() {
  const availableProxies = availableSigningProxies();
  if (availableProxies.length === 1) return availableProxies[0].id;
  return document.querySelector("#signing-proxy").value || null;
}

function renderSelectedSigner(identity) {
  const container = document.querySelector("#selected-signer");
  container.replaceChildren();
  if (!identity) {
    container.textContent = "Nessun certificato disponibile.";
    return;
  }
  const name = document.createElement("strong");
  name.textContent = identity.display_name;
  const details = document.createElement("dl");
  for (const [label, value] of [
    ["Soggetto", identity.subject],
    ["Emittente", identity.issuer],
    ["Numero di serie", identity.serial_number],
    ["Validità", `${formatDate(identity.not_valid_before)} – ${formatDate(identity.not_valid_after)}`],
    ["Chiave", identity.key_bits ? `${identity.key_bits} bit` : null],
  ]) {
    if (value === null) continue;
    const row = document.createElement("div");
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = value;
    row.append(term, description);
    details.append(row);
  }
  container.append(name, details);
  // Signing is never blocked here: the operator is told, and decides.
  if (identity.intended_use === "authentication") {
    const note = document.createElement("p");
    note.className = "pdfa-note";
    note.textContent = "Il certificato selezionato è pensato per l'autenticazione e non per la firma di documenti. Un file firmato con questo certificato potrebbe comunque essere accettato in alcuni contesti.";
    container.append(note);
  }
  if (identity.key_bits && identity.key_bits < 2048) {
    const note = document.createElement("p");
    note.className = "pdfa-note failed";
    note.textContent = `La chiave di questo certificato è di ${identity.key_bits} bit, sotto i 2048 richiesti dagli standard attuali. La firma resta valida, ma alcuni programmi di verifica potrebbero segnalarla come debole o rifiutarla.`;
    container.append(note);
  }
}

function updateSignMode() {
  const mode = document.querySelector("#signature-mode").value;
  const graphic = mode === "graphic";
  const pades = mode === "pades";
  const cmsInput = signingDocument?.input_format === "cms_attached";
  const catalogueReady = graphicSignatures.length > 0;
  const padesGraphicBox = document.querySelector("#pades-graphic");
  if (!catalogueReady || !pades) padesGraphicBox.checked = false;
  padesGraphicBox.disabled = !catalogueReady;
  document.querySelector("#pades-graphic-field").hidden = !pades;
  const padesNote = document.querySelector("#pades-graphic-note");
  padesNote.hidden = !pades || catalogueReady;
  padesNote.textContent = "Nessuna firma grafica nel catalogo: la firma PAdES resta disponibile, ma senza immagine visibile.";
  document.querySelector("#cades-strategy-field").hidden = mode !== "cades" || !cmsInput;
  document.querySelector("#xades-packaging-field").hidden = mode !== "xades";
  document.querySelector("#proxy-field").hidden = graphic;
  document.querySelector("#graphic-fields").hidden = !(graphic || (pades && padesGraphicBox.checked));
  const selectedCertificate = selectedCertificateConfig();
  const needsPin = !graphic && selectedCertificate?.backend === "local" && selectedCertificate.requires_pin;
  document.querySelector("#signing-pin-field").hidden = !needsPin;
  const identity = selectedProxyIdentity();
  renderSelectedSigner(identity);
  updateSignSummary();
}

function updateSignSummary() {
  const mode = document.querySelector("#signature-mode").value;
  const summary = document.querySelector("#sign-summary");
  const pdfaHolder = document.querySelector("#sign-pdfa");
  pdfaHolder.replaceChildren();
  const pdfaNote = pdfaWarning(signingDocument);
  if (pdfaNote) pdfaHolder.append(pdfaNote);
  if (mode === "graphic") {
    summary.textContent = placements.length ? `${placements.length} posizione/i configurata/e. Questa modalità applica soltanto l'immagine, senza firma digitale.` : "Aggiungi almeno una posizione per continuare.";
  } else if (mode === "xades") {
    const identity = selectedProxyIdentity();
    const packaging = document.querySelector("#xades-packaging").value;
    const shape = packaging === "enveloping"
      ? " in un nuovo XML contenitore, che conserva il file originale intatto"
      : " inserendo la firma nell'XML";
    summary.textContent = identity ? `Conferma: il file verrà firmato in formato XAdES${shape} da ${identity.display_name}.` : "Seleziona un certificato disponibile.";
  } else if (mode === "pades") {
    const identity = selectedProxyIdentity();
    const wantsGraphic = document.querySelector("#pades-graphic").checked;
    if (!identity) {
      summary.textContent = "Seleziona un certificato disponibile.";
    } else if (wantsGraphic && placements.length !== 1) {
      summary.textContent = "Posiziona una sola immagine: diventerà l'aspetto della firma, quello che si apre cliccandola nel lettore PDF.";
    } else {
      const appearance = wantsGraphic ? " con l'immagine scelta come aspetto della firma" : " senza immagine visibile";
      summary.textContent = `Conferma: il PDF verrà firmato in formato PAdES${appearance} da ${identity.display_name}.`;
    }
  } else {
    const identity = selectedProxyIdentity();
    const strategy = document.querySelector("#cades-strategy").value;
    const strategyText = signingDocument?.input_format === "cms_attached"
      ? (strategy === "parallel" ? " con una firma parallela alle firme esistenti" : " aggiungendo un nuovo livello a matrioska")
      : "";
    summary.textContent = identity ? `Conferma: il file verrà firmato in formato CAdES${strategyText} da ${identity.display_name}.` : "Seleziona un certificato disponibile.";
  }
}

function findGraphicVersion(versionId) {
  for (const graphic of graphicSignatures) {
    const version = graphic.versions.find((candidate) => candidate.id === versionId);
    if (version) return { graphic, version };
  }
  return null;
}

async function addPlacement() {
  try {
    if (document.querySelector("#signature-mode").value === "pades" && placements.length >= 1) {
      throw new Error("La firma PAdES ammette una sola immagine. Rimuovi quella presente per spostarla.");
    }
    const versionId = document.querySelector("#graphic-signature").value;
    const selected = findGraphicVersion(versionId);
    const preview = await pdfPreviewPromise;
    if (!selected || !preview) throw new Error("Seleziona una firma grafica disponibile.");
    const stage = document.querySelector("#pdf-stage");
    const width = 0.25;
    const pageRatio = stage.clientWidth / stage.clientHeight;
    const imageRatio = selected.version.height_pixels / selected.version.width_pixels;
    const height = Math.min(0.3, Math.max(0.04, width * pageRatio * imageRatio));
    const placement = {
      _clientId: `posizionamento-${++placementCounter}`,
      graphic_signature_version_id: versionId,
      page: preview.currentPageNumber(),
      x: Math.max(0, 0.7 - width),
      y: Math.max(0, 0.85 - height),
      width,
      height,
      order: placements.length,
    };
    placements.push(placement);
    selectedPlacementId = placement._clientId;
    renderPlacements();
  } catch (error) {
    showNotice(error.message, "error");
  }
}

function renderPlacements() {
  const list = document.querySelector("#placements");
  list.replaceChildren();
  placements.forEach((placement, index) => {
    const item = document.createElement("li");
    item.classList.toggle("selected", placement._clientId === selectedPlacementId);
    const selected = findGraphicVersion(placement.graphic_signature_version_id);
    const text = document.createElement("button");
    text.type = "button";
    text.className = "placement-link";
    text.textContent = `${selected?.graphic.name || "Firma grafica"} · pagina ${placement.page}`;
    text.addEventListener("click", async () => {
      selectedPlacementId = placement._clientId;
      const preview = await pdfPreviewPromise;
      await preview.showPage(placement.page);
      renderPlacements();
    });
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "text-button";
    remove.textContent = "Rimuovi";
    remove.addEventListener("click", () => {
      placements.splice(index, 1);
      placements = placements.map((entry, order) => ({ ...entry, order }));
      renderPlacements();
    });
    item.append(text, remove);
    list.append(item);
  });
  document.querySelector("#remove-placement").disabled = !selectedPlacementId;
  renderPlacementLayer();
  updateSignSummary();
}

function renderPlacementLayer() {
  const layer = document.querySelector("#placement-layer");
  layer.replaceChildren();
  const page = Number(document.querySelector("#pdf-stage").dataset.pageNumber || 0);
  for (const placement of placements.filter((entry) => entry.page === page)) {
    const selected = findGraphicVersion(placement.graphic_signature_version_id);
    if (!selected) continue;
    const element = document.createElement("div");
    element.className = "graphic-placement";
    element.classList.toggle("selected", placement._clientId === selectedPlacementId);
    element.style.left = `${placement.x * 100}%`;
    element.style.top = `${placement.y * 100}%`;
    element.style.width = `${placement.width * 100}%`;
    element.style.height = `${placement.height * 100}%`;
    const image = document.createElement("img");
    image.alt = selected.graphic.name;
    image.draggable = false;
    image.src = `/api/v1/graphic-signatures/${selected.graphic.id}/versions/${selected.version.version_number}/image`;
    const handle = document.createElement("span");
    handle.className = "resize-handle";
    handle.setAttribute("aria-label", "Ridimensiona firma");
    element.append(image, handle);
    element.addEventListener("pointerdown", (event) => {
      if (event.target === handle) return;
      startPlacementGesture(event, placement, element, false);
    });
    handle.addEventListener("pointerdown", (event) => {
      event.stopPropagation();
      startPlacementGesture(event, placement, element, true);
    });
    layer.append(element);
  }
}

function startPlacementGesture(event, placement, element, resizing) {
  event.preventDefault();
  selectedPlacementId = placement._clientId;
  document.querySelectorAll(".graphic-placement").forEach((candidate) => candidate.classList.remove("selected"));
  element.classList.add("selected");
  document.querySelector("#remove-placement").disabled = false;
  const stage = document.querySelector("#pdf-stage");
  const startX = event.clientX;
  const startY = event.clientY;
  const initial = { x: placement.x, y: placement.y, width: placement.width, height: placement.height };
  element.setPointerCapture(event.pointerId);
  const move = (moveEvent) => {
    const deltaX = (moveEvent.clientX - startX) / stage.clientWidth;
    const deltaY = (moveEvent.clientY - startY) / stage.clientHeight;
    if (resizing) {
      placement.width = Math.min(1 - placement.x, Math.max(0.03, initial.width + deltaX));
      placement.height = Math.min(1 - placement.y, Math.max(0.03, initial.height + deltaY));
      element.style.width = `${placement.width * 100}%`;
      element.style.height = `${placement.height * 100}%`;
    } else {
      placement.x = Math.min(1 - placement.width, Math.max(0, initial.x + deltaX));
      placement.y = Math.min(1 - placement.height, Math.max(0, initial.y + deltaY));
      element.style.left = `${placement.x * 100}%`;
      element.style.top = `${placement.y * 100}%`;
    }
  };
  const finish = () => {
    element.removeEventListener("pointermove", move);
    element.removeEventListener("pointerup", finish);
    element.removeEventListener("pointercancel", finish);
    renderPlacements();
  };
  element.addEventListener("pointermove", move);
  element.addEventListener("pointerup", finish);
  element.addEventListener("pointercancel", finish);
}

function removeSelectedPlacement() {
  const index = placements.findIndex((placement) => placement._clientId === selectedPlacementId);
  if (index < 0) return;
  placements.splice(index, 1);
  placements = placements.map((placement, order) => ({ ...placement, order }));
  selectedPlacementId = null;
  renderPlacements();
}

async function submitSignature(event) {
  event.preventDefault();
  if (!signingDocument) return;
  const mode = document.querySelector("#signature-mode").value;
  const padesGraphic = mode === "pades" && document.querySelector("#pades-graphic").checked;
  if (mode === "graphic" && placements.length === 0) {
    showNotice("Aggiungi e posiziona almeno una firma sul documento.", "error");
    return;
  }
  if (padesGraphic && placements.length !== 1) {
    showNotice("La firma PAdES ammette una sola immagine: è l'aspetto della firma.", "error");
    return;
  }
  const apiPlacements = placements.map(({ _clientId, ...placement }) => placement);
  const payload = { mode, placements: mode === "graphic" || padesGraphic ? apiPlacements : [] };
  if (mode === "cades" && signingDocument.input_format === "cms_attached") {
    payload.cades_strategy = document.querySelector("#cades-strategy").value;
  }
  if (mode === "xades") {
    payload.xades_packaging = document.querySelector("#xades-packaging").value;
  }
  const digital = mode === "cades" || mode === "pades" || mode === "xades";
  const proxyId = selectedProxyId();
  if (digital && proxyId) payload.signing_proxy_id = proxyId;
  const pinInput = document.querySelector("#signing-pin");
  const selectedCertificate = selectedCertificateConfig();
  if (digital && selectedCertificate?.backend === "local" && selectedCertificate.requires_pin) {
    if (!pinInput.value) {
      showNotice("Inserisci il PIN della smart card.", "error");
      return;
    }
    payload.pin = pinInput.value;
  }
  pinInput.value = "";
  const button = document.querySelector("#confirm-sign");
  button.disabled = true;
  try {
    const job = await api(`/api/v1/documents/${signingDocument.id}/signatures`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    activeJobId = job.id;
    activeDocumentJobs.set(job.document_id, job);
    document.querySelector("#sign-config").hidden = true;
    document.querySelector("#sign-progress").hidden = false;
    renderJobStatus(job);
    await loadDocuments();
    scheduleJobPoll();
  } catch (error) {
    showNotice(error.message, "error");
    button.disabled = false;
  }
}

function renderJobStatus(job) {
  const [title, fallback] = jobLabels[job.status] || [job.status, ""];
  document.querySelector("#progress-title").textContent = title;
  document.querySelector("#progress-message").textContent = job.error_message || fallback;
  const progress = document.querySelector("#sign-progress");
  progress.className = `progress-card ${job.status}`;
  const terminal = ["completed", "failed"].includes(job.status);
  progress.querySelector(".spinner").hidden = terminal;
  const confirm = document.querySelector("#confirm-sign");
  confirm.hidden = job.status === "completed";
  confirm.disabled = job.status !== "failed";
  if (job.status === "failed") {
    document.querySelector("#sign-config").hidden = false;
    confirm.textContent = "Riprova";
    updateSignMode();
  }
  if (job.status === "completed") {
    const download = document.querySelector("#download-result");
    download.href = `/api/v1/documents/${job.document_id}/result`;
    download.hidden = false;
    activeDocumentJobs.delete(job.document_id);
  }
  if (job.status === "failed") activeDocumentJobs.delete(job.document_id);
}

function scheduleJobPoll() {
  clearTimeout(jobPollTimer);
  if (!activeJobId) return;
  jobPollTimer = setTimeout(async () => {
    try {
      const job = await api(`/api/v1/signature-jobs/${activeJobId}`);
      handleJobUpdate(job);
    } catch (error) {
      document.querySelector("#progress-message").textContent = "Aggiornamento in tempo reale interrotto; nuovo tentativo in corso…";
    }
    if (activeJobId) scheduleJobPoll();
  }, eventSocket?.readyState === WebSocket.OPEN ? 5000 : 1500);
}

function handleJobUpdate(job) {
  if (["queued", "running"].includes(job.status)) activeDocumentJobs.set(job.document_id, job);
  else activeDocumentJobs.delete(job.document_id);
  if (job.id === activeJobId) {
    renderJobStatus(job);
    if (["completed", "failed"].includes(job.status)) {
      activeJobId = null;
      clearTimeout(jobPollTimer);
      loadDocuments().catch(() => {});
    }
  }
}

async function loadOwnerCandidates() {
  const select = document.querySelector("#owner-select");
  const search = document.querySelector("#owner-dialog-search").value.trim();
  select.replaceChildren();
  try {
    const listing = await api(`/api/v1/admin/users?${ownerCandidateQuery({ limit: 50, search })}`);
    const candidates = listing.items.filter((user) => user.id !== ownerDocument?.owner_user_id);
    for (const user of candidates) {
      const option = document.createElement("option");
      option.value = user.id;
      option.textContent = `${user.display_name} (${roleLabels[user.role]})`;
      select.append(option);
    }
    document.querySelector("#owner-dialog-more").hidden = listing.total <= listing.items.length;
  } catch (error) {
    showNotice(error.message, "error");
  }
  document.querySelector("#confirm-owner").disabled = select.options.length === 0;
}

function openOwnerDialog(item) {
  ownerDocument = item;
  document.querySelector("#owner-dialog-document").textContent = item.original_name;
  document.querySelector("#owner-dialog-search").value = "";
  document.querySelector("#owner-select").replaceChildren();
  document.querySelector("#confirm-owner").disabled = true;
  document.querySelector("#owner-dialog").showModal();
  loadOwnerCandidates();
}

async function changeSelectedOwner() {
  if (!ownerDocument) return;
  const userId = document.querySelector("#owner-select").value;
  const button = document.querySelector("#confirm-owner");
  if (!userId) return;
  button.disabled = true;
  try {
    await api(`/api/v1/admin/documents/${ownerDocument.id}/owner`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ owner_user_id: userId }),
    });
    showNotice("Proprietario aggiornato.");
    await loadDocuments();
  } catch (error) {
    showNotice(error.message, "error");
  } finally {
    ownerDocument = null;
    button.disabled = false;
  }
}

async function uploadDocument(file) {
  const data = new FormData();
  data.append("file", file);
  try {
    await api("/api/v1/documents", { method: "POST", body: data });
    showNotice("Documento caricato.");
    await loadDocuments();
  } catch (error) {
    showNotice(error.message, "error");
  }
}

// A bare row of inputs says nothing about what each one holds: every field
// carries its name above it.
function labelledField(text, input) {
  const label = document.createElement("label");
  label.className = "field";
  label.append(document.createTextNode(text), input);
  return label;
}

function renderAdminGraphics(items) {
  adminGraphics = items;
  const container = document.querySelector("#graphics-admin");
  if (!container.dataset.dropBound) {
    graphicReordering.bindDragAndDrop(container);
    container.dataset.dropBound = "true";
  }
  container.replaceChildren();
  document.querySelector("#graphic-order-help").hidden = !items.length;
  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "Il catalogo è vuoto.";
    container.append(empty);
    return;
  }
  for (const [index, graphic] of items.entries()) {
    const card = document.createElement("article");
    card.dataset.graphicId = graphic.id;
    card.addEventListener("dragstart", (event) => {
      event.dataTransfer.effectAllowed = "move";
      card.classList.add("dragging");
    });
    card.addEventListener("dragend", () => {
      card.classList.remove("dragging");
      card.draggable = false;
      graphicReordering.adoptRenderedOrder(container);
    });
    card.className = "admin-card";
    const current = currentGraphicVersion(graphic);
    const header = document.createElement("div");
    header.className = "admin-card-header";
    const preview = document.createElement("img");
    preview.className = "graphic-thumb";
    preview.alt = `Anteprima di ${graphic.name}`;
    if (current) preview.src = `/api/v1/graphic-signatures/${graphic.id}/versions/${current.version_number}/image`;
    const title = document.createElement("div");
    const heading = document.createElement("strong");
    heading.textContent = graphic.name;
    const meta = document.createElement("span");
    meta.className = "user-meta";
    const predefinita = index === 0 && graphic.active ? " · Predefinita" : "";
    meta.textContent = `Versione corrente ${graphic.current_version_number} · ${graphic.active ? "Attiva" : "Disattivata"}${predefinita}`;
    title.append(heading, meta);
    header.append(preview, title, graphicReordering.controls(graphic, index, items.length));

    const editor = document.createElement("div");
    editor.className = "admin-editor";
    const name = document.createElement("input");
    name.value = graphic.name;
    const description = document.createElement("input");
    description.value = graphic.description;
    const activeLabel = document.createElement("label");
    activeLabel.className = "check-field";
    const active = document.createElement("input");
    active.type = "checkbox";
    active.checked = graphic.active;
    activeLabel.append(active, document.createTextNode("Attiva"));
    const save = document.createElement("button");
    save.className = "button";
    save.textContent = "Salva";
    save.addEventListener("click", async () => {
      save.disabled = true;
      try {
        await api(`/api/v1/admin/graphic-signatures/${graphic.id}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: name.value, description: description.value, active: active.checked }),
        });
        showNotice("Firma grafica aggiornata.");
        await Promise.all([loadAdminGraphics(), loadSigningResources()]);
        await loadDocuments();
      } catch (error) {
        showNotice(error.message, "error");
        save.disabled = false;
      }
    });
    editor.append(
      labelledField("Nome", name),
      labelledField("Descrizione", description),
      activeLabel,
      save,
    );

    const versions = document.createElement("div");
    versions.className = "version-list";
    for (const version of [...graphic.versions].sort((a, b) => b.version_number - a.version_number)) {
      const line = document.createElement("div");
      const link = document.createElement("a");
      link.href = `/api/v1/graphic-signatures/${graphic.id}/versions/${version.version_number}/image`;
      link.textContent = `Versione ${version.version_number} · ${version.width_pixels} × ${version.height_pixels} px`;
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "text-button";
      remove.textContent = "Elimina";
      const ultima = graphic.versions.length === 1;
      remove.addEventListener("click", async () => {
        const domanda = ultima
          ? `Eliminare la versione ${version.version_number} di ${graphic.name}? È l'unica, quindi verrà rimossa l'intera firma grafica.`
          : version.version_number === graphic.current_version_number
            ? `Eliminare la versione ${version.version_number} di ${graphic.name}? Tornerà in uso la versione precedente.`
            : `Eliminare la versione ${version.version_number} di ${graphic.name}?`;
        if (!window.confirm(domanda)) return;
        try {
          await api(`/api/v1/admin/graphic-signatures/${graphic.id}/versions/${version.version_number}`, { method: "DELETE" });
          showNotice(ultima ? "Firma grafica eliminata." : "Versione eliminata.");
          await loadAdminGraphics();
          await loadSigningResources();
        } catch (error) {
          showNotice(error.message, "error");
        }
      });
      line.append(link, remove);
      versions.append(line);
    }

    const versionForm = document.createElement("form");
    versionForm.className = "inline-upload";
    const file = document.createElement("input");
    file.type = "file";
    file.accept = "image/png";
    file.required = true;
    const upload = document.createElement("button");
    upload.className = "button small";
    upload.type = "submit";
    upload.textContent = "Carica nuova versione";
    versionForm.append(file, upload);
    versionForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!file.files[0]) return;
      const data = new FormData();
      data.append("image", file.files[0]);
      upload.disabled = true;
      try {
        await api(`/api/v1/admin/graphic-signatures/${graphic.id}/versions`, { method: "POST", body: data });
        showNotice("Nuova versione caricata.");
        await Promise.all([loadAdminGraphics(), loadSigningResources()]);
      } catch (error) {
        showNotice(error.message, "error");
        upload.disabled = false;
      }
    });
    card.append(header, editor, versions, versionForm);
    container.append(card);
  }
}

async function loadAdminGraphics() {
  const listing = await api("/api/v1/admin/graphic-signatures");
  renderAdminGraphics(listing.items);
}

const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

// Reordering, shared by the certificates and by the graphic signatures: arrows
// for the keyboard, a handle for the mouse, and saves that queue instead of
// racing. The caller says where the cards live, how to read and replace the
// list, and how to redraw it.
function createReordering({ container, datasetKey, endpoint, read, write, render, reload, label }) {
  let saving = Promise.resolve();
  let queued = false;

  const cards = () => document.querySelectorAll(`${container} .admin-card`);

  function cardTops() {
    const tops = new Map();
    for (const card of cards()) tops.set(card.dataset[datasetKey], card.getBoundingClientRect().top);
    return tops;
  }

  // Take the cards back to where they were, then let them slide into the new
  // order, so a click on an arrow reads as a movement rather than a redraw.
  function animate(previousTops) {
    if (reducedMotion.matches) return;
    for (const card of cards()) {
      const previousTop = previousTops.get(card.dataset[datasetKey]);
      if (previousTop === undefined) continue;
      const shift = previousTop - card.getBoundingClientRect().top;
      if (!shift) continue;
      card.animate(
        [{ transform: `translateY(${shift}px)` }, { transform: "none" }],
        { duration: 180, easing: "ease-out" },
      );
    }
  }

  // Two arrow clicks in a row must not race: the saves run one after the other,
  // and a save still queued simply picks up the latest order when its turn comes.
  function persist() {
    if (queued) return saving;
    queued = true;
    saving = saving.then(async () => {
      queued = false;
      try {
        await api(endpoint, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ids: read().map((item) => item.id) }),
        });
        await loadSigningResources();
      } catch (error) {
        showNotice(error.message, "error");
        await reload();
      }
    });
    return saving;
  }

  function move(from, to) {
    const items = read();
    if (to < 0 || to >= items.length || from === to) return;
    const previousTops = cardTops();
    const [moved] = items.splice(from, 1);
    items.splice(to, 0, moved);
    write(items);
    render();
    animate(previousTops);
    persist();
  }

  function cardBelow(node, pointerY) {
    return [...node.querySelectorAll(".admin-card:not(.dragging)")].find(
      (card) => pointerY < card.getBoundingClientRect().top + card.offsetHeight / 2,
    );
  }

  return {
    controls(item, index, total) {
      const controls = document.createElement("div");
      controls.className = "order-controls";
      const handle = document.createElement("span");
      handle.className = "drag-handle";
      handle.title = "Trascina per riordinare";
      handle.textContent = "⠿";
      // The card is only draggable while the handle is held, so the fields
      // inside it stay selectable.
      handle.addEventListener("pointerdown", () => { handle.closest(".admin-card").draggable = true; });
      handle.addEventListener("pointerup", () => { handle.closest(".admin-card").draggable = false; });
      controls.append(handle);
      for (const [direction, symbol, target] of [
        ["in su", "↑", index - 1],
        ["in giù", "↓", index + 1],
      ]) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "icon-button";
        button.textContent = symbol;
        button.setAttribute("aria-label", `Sposta ${label(item)} ${direction}`);
        button.disabled = target < 0 || target >= total;
        button.addEventListener("click", () => move(index, target));
        controls.append(button);
      }
      return controls;
    },

    bindDragAndDrop(node) {
      node.addEventListener("dragover", (event) => {
        const dragged = node.querySelector(".admin-card.dragging");
        if (!dragged) return;
        event.preventDefault();
        const below = cardBelow(node, event.clientY);
        if (below) node.insertBefore(dragged, below);
        else node.append(dragged);
      });
      node.addEventListener("drop", (event) => event.preventDefault());
    },

    adoptRenderedOrder(node) {
      const items = read();
      const byId = new Map(items.map((item) => [item.id, item]));
      const rearranged = [...node.querySelectorAll(".admin-card")].map(
        (card) => byId.get(card.dataset[datasetKey]),
      );
      if (rearranged.some((item, index) => item !== items[index])) {
        write(rearranged);
        render();
        persist();
      }
    },
  };
}

const proxyReordering = createReordering({
  container: "#proxies-admin",
  datasetKey: "proxyId",
  endpoint: "/api/v1/admin/signing-proxies/order",
  read: () => adminProxies,
  write: (items) => { adminProxies = items; },
  render: () => renderAdminProxies(adminProxies),
  reload: () => loadAdminProxies(),
  label: (proxy) => proxy.name,
});

const graphicReordering = createReordering({
  container: "#graphics-admin",
  datasetKey: "graphicId",
  endpoint: "/api/v1/admin/graphic-signatures/order",
  read: () => adminGraphics,
  write: (items) => { adminGraphics = items; },
  render: () => renderAdminGraphics(adminGraphics),
  reload: () => loadAdminGraphics(),
  label: (graphic) => graphic.name,
});

function renderAdminProxies(items) {
  adminProxies = items;
  const container = document.querySelector("#proxies-admin");
  if (!container.dataset.dropBound) {
    proxyReordering.bindDragAndDrop(container);
    container.dataset.dropBound = "true";
  }
  container.replaceChildren();
  document.querySelector("#certificate-order-help").hidden = !items.length;
  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "Non è configurato alcun certificato.";
    container.append(empty);
    return;
  }
  for (const [index, proxy] of items.entries()) {
    const card = document.createElement("article");
    card.className = "admin-card";
    card.dataset.proxyId = proxy.id;
    card.addEventListener("dragstart", (event) => {
      event.dataTransfer.effectAllowed = "move";
      card.classList.add("dragging");
    });
    card.addEventListener("dragend", () => {
      card.classList.remove("dragging");
      card.draggable = false;
      proxyReordering.adoptRenderedOrder(container);
    });
    const header = document.createElement("div");
    header.className = "admin-card-header";
    const title = document.createElement("div");
    const heading = document.createElement("strong");
    heading.textContent = proxy.name;
    const meta = document.createElement("span");
    meta.className = "user-meta";
    const backendLabel = proxy.backend === "local" ? "Locale" : "PKCS11 Web Proxy";
    const pinLabel = proxy.backend === "local" ? ` · PIN ${proxy.pin_saved ? "salvato" : "richiesto a ogni firma"}` : "";
    meta.textContent = `${backendLabel} · Configurazione v${proxy.version} · ${proxy.active ? "Attivo" : "Disattivato"}${pinLabel}`;
    title.append(heading, meta);
    header.append(title, proxyReordering.controls(proxy, index, items.length));

    const editor = document.createElement("div");
    editor.className = "admin-editor proxy-editor";
    const name = document.createElement("input");
    name.value = proxy.name;
    const configurationFields = [labelledField("Nome", name)];
    const configurationInputs = [];
    if (proxy.backend === "local") {
      for (const [field, label, value] of [
        ["pkcs11_library_path", "Libreria PKCS#11", proxy.pkcs11_library_path],
        ["pkcs11_token_label", "Nome token", proxy.pkcs11_token_label],
        ["pkcs11_certificate_label", "Nome certificato PKCS#11", proxy.pkcs11_certificate_label],
      ]) {
        const input = document.createElement("input");
        input.value = value || "";
        input.dataset.field = field;
        configurationInputs.push(input);
        configurationFields.push(labelledField(label, input));
      }
    } else {
      const url = document.createElement("input");
      url.value = proxy.base_url || "";
      url.type = "url";
      url.dataset.field = "base_url";
      configurationInputs.push(url);
      configurationFields.push(labelledField("URL del PKCS11 Web Proxy", url));
    }
    const activeLabel = document.createElement("label");
    activeLabel.className = "check-field";
    const active = document.createElement("input");
    active.type = "checkbox";
    active.checked = proxy.active;
    activeLabel.append(active, document.createTextNode("Attivo"));
    const save = document.createElement("button");
    save.className = "button";
    save.textContent = "Salva";
    save.addEventListener("click", async () => {
      save.disabled = true;
      try {
        const body = { name: name.value, active: active.checked };
        configurationInputs.forEach((input) => { body[input.dataset.field] = input.value; });
        await api(`/api/v1/admin/signing-proxies/${proxy.id}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        showNotice("Certificato aggiornato.");
        await Promise.all([loadAdminProxies(), loadSigningResources()]);
      } catch (error) {
        showNotice(error.message, "error");
        save.disabled = false;
      }
    });
    const check = document.createElement("button");
    check.className = "button";
    check.textContent = "Verifica certificato";
    check.addEventListener("click", async () => {
      check.disabled = true;
      try {
        const result = await api(`/api/v1/admin/signing-proxies/${proxy.id}/check`, { method: "POST" });
        showNotice(result.available && result.identity ? `${proxy.name}: disponibile, certificato di ${result.identity.display_name}.` : `${proxy.name}: non disponibile.`, result.available ? "success" : "error");
      } catch (error) {
        showNotice(error.message, "error");
      } finally {
        check.disabled = false;
      }
    });
    const removeProxy = document.createElement("button");
    removeProxy.className = "button danger";
    removeProxy.textContent = "Elimina";
    removeProxy.addEventListener("click", async () => {
      if (!window.confirm(`Eliminare il certificato “${proxy.name}”? I documenti già firmati con esso restano invariati.`)) return;
      removeProxy.disabled = true;
      try {
        await api(`/api/v1/admin/signing-proxies/${proxy.id}`, { method: "DELETE" });
        showNotice("Certificato eliminato.");
        await Promise.all([loadAdminProxies(), loadSigningResources()]);
      } catch (error) {
        showNotice(error.message, "error");
        removeProxy.disabled = false;
      }
    });
    editor.append(...configurationFields, activeLabel, save, check, removeProxy);
    if (proxy.backend === "local") {
      const pinEditor = document.createElement("div");
      pinEditor.className = "inline-upload";
      const pin = document.createElement("input");
      pin.type = "password";
      pin.inputMode = "numeric";
      pin.autocomplete = "new-password";
      pin.placeholder = proxy.pin_saved ? "Nuovo PIN" : "PIN da salvare";
      pin.setAttribute("aria-label", proxy.pin_saved ? "Nuovo PIN" : "PIN da salvare");
      const savePin = document.createElement("button");
      savePin.className = "button";
      savePin.textContent = proxy.pin_saved ? "Sostituisci PIN" : "Salva PIN";
      savePin.addEventListener("click", async () => {
        if (!pin.value) {
          showNotice("Inserisci il PIN.", "error");
          return;
        }
        savePin.disabled = true;
        try {
          await api(`/api/v1/admin/signing-proxies/${proxy.id}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ saved_pin_action: "replace", pin: pin.value }),
          });
          pin.value = "";
          showNotice(proxy.pin_saved ? "PIN sostituito." : "PIN salvato in forma cifrata.");
          await Promise.all([loadAdminProxies(), loadSigningResources()]);
        } catch (error) {
          showNotice(error.message, "error");
          savePin.disabled = false;
        }
      });
      pinEditor.append(pin, savePin);
      if (proxy.pin_saved) {
        const removePin = document.createElement("button");
        removePin.className = "button danger";
        removePin.textContent = "Rimuovi PIN";
        removePin.addEventListener("click", async () => {
          removePin.disabled = true;
          try {
            await api(`/api/v1/admin/signing-proxies/${proxy.id}`, {
              method: "PATCH",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ saved_pin_action: "remove" }),
            });
            showNotice("PIN rimosso.");
            await Promise.all([loadAdminProxies(), loadSigningResources()]);
          } catch (error) {
            showNotice(error.message, "error");
            removePin.disabled = false;
          }
        });
        pinEditor.append(removePin);
      }
      card.append(header, editor, pinEditor);
    } else {
      card.append(header, editor);
    }
    container.append(card);
  }
}

async function loadAdminProxies() {
  const listing = await api("/api/v1/admin/signing-proxies");
  renderAdminProxies(listing.items);
}

// Without a deployment secret the PIN is stored as typed; say so plainly, but
// only once someone actually asks to save one.
let pinEncryptionEnabled = true;

function updatePinEncryptionWarning() {
  const saving = document.querySelector("#new-save-pin").checked;
  document.querySelector("#pin-encryption-warning").hidden = pinEncryptionEnabled || !saving;
}

async function loadKnownPkcs11Libraries() {
  const result = await api("/api/v1/admin/signing-proxies/local/libraries");
  pinEncryptionEnabled = result.pin_encryption_enabled !== false;
  document.querySelector("#save-pin-label").textContent =
    pinEncryptionEnabled ? "Salva il PIN cifrato" : "Salva il PIN (in chiaro)";
  updatePinEncryptionWarning();
  const choice = document.querySelector("#new-pkcs11-library-choice");
  const previousPath = selectedLocalLibraryPath();
  choice.replaceChildren();
  result.items.forEach((path) => {
    const option = document.createElement("option");
    option.value = path;
    option.textContent = path;
    option.selected = path === previousPath;
    choice.append(option);
  });
  const other = document.createElement("option");
  other.value = "__other__";
  other.textContent = "Altro…";
  if (previousPath && !result.items.includes(previousPath)) {
    other.selected = true;
    document.querySelector("#new-pkcs11-library").value = previousPath;
  }
  choice.append(other);
  if (!choice.value) choice.value = result.items.length ? result.items[0] : "__other__";
  updateLocalLibraryChoice();
  if (
    document.querySelector("#new-certificate-backend").value === "local"
    && selectedLocalLibraryPath()
  ) {
    await discoverLocalCertificates({ announce: false });
  }
}

function selectedLocalLibraryPath() {
  const choice = document.querySelector("#new-pkcs11-library-choice");
  if (!choice || choice.value === "__other__") {
    return document.querySelector("#new-pkcs11-library")?.value.trim() || "";
  }
  return choice.value;
}

function clearLocalCertificateDiscovery(message = "Seleziona un middleware.", invalidate = true) {
  if (invalidate) localDiscoveryToken += 1;
  discoveredLocalCertificates = [];
  const select = document.querySelector("#new-pkcs11-certificate");
  select.replaceChildren();
  const option = document.createElement("option");
  option.value = "";
  option.textContent = message;
  select.append(option);
  select.disabled = true;
}

function updateLocalLibraryChoice() {
  const custom = document.querySelector("#new-pkcs11-library-choice").value === "__other__";
  document.querySelector("#new-pkcs11-library-custom-field").hidden = !custom;
  document.querySelector("#new-pkcs11-library").required = custom;
}

async function localLibraryExists(path) {
  const result = await api("/api/v1/admin/signing-proxies/local/library-status", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ library_path: path }),
  });
  return result.exists;
}

async function discoverLocalCertificates({ announce = true, checkExists = false } = {}) {
  const path = selectedLocalLibraryPath();
  const button = document.querySelector("#discover-pkcs11");
  if (!path) {
    clearLocalCertificateDiscovery();
    return;
  }
  const token = ++localDiscoveryToken;
  if (checkExists && !(await localLibraryExists(path))) {
    if (token === localDiscoveryToken) {
      clearLocalCertificateDiscovery("Il file non esiste.");
    }
    return;
  }
  button.disabled = true;
  clearLocalCertificateDiscovery("Rilevamento in corso…");
  const requestToken = localDiscoveryToken;
  try {
    const result = await api("/api/v1/admin/signing-proxies/local/discover", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ library_path: path }),
    });
    if (requestToken !== localDiscoveryToken || path !== selectedLocalLibraryPath()) return;
    discoveredLocalCertificates = result.items;
    const select = document.querySelector("#new-pkcs11-certificate");
    select.replaceChildren();
    result.items.forEach((item, index) => {
      const option = document.createElement("option");
      option.value = String(index);
      option.textContent = `${item.identity.display_name} — ${item.certificate_label} (token ${item.token_label})`;
      select.append(option);
    });
    select.disabled = result.items.length === 0;
    if (!result.items.length) clearLocalCertificateDiscovery("Nessun certificato rilevato.", false);
    if (announce) showNotice(result.items.length ? `${result.items.length} certificati rilevati.` : "Nessun certificato rilevato.", result.items.length ? "success" : "error");
  } catch (error) {
    if (requestToken !== localDiscoveryToken) return;
    clearLocalCertificateDiscovery("Rilevamento non riuscito.", false);
    if (announce) showNotice(error.message, "error");
  } finally {
    if (requestToken === localDiscoveryToken) button.disabled = false;
  }
}

function handleRealtimeSnapshot(snapshot) {
  const fingerprint = JSON.stringify(snapshot);
  if (fingerprint === realtimeFingerprint) return;
  realtimeFingerprint = fingerprint;
  activeDocumentJobs.clear();
  for (const job of snapshot.jobs) {
    if (["queued", "running"].includes(job.status) && !activeDocumentJobs.has(job.document_id)) {
      activeDocumentJobs.set(job.document_id, job);
    }
    if (job.id === activeJobId) handleJobUpdate(job);
  }
  loadDocuments().catch(() => {});
}

function connectEvents() {
  clearTimeout(reconnectTimer);
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  eventSocket = new WebSocket(`${protocol}//${window.location.host}/api/v1/events`);
  eventSocket.addEventListener("message", (event) => {
    const payload = JSON.parse(event.data);
    if (payload.type === "snapshot") handleRealtimeSnapshot(payload);
  });
  eventSocket.addEventListener("close", () => {
    eventSocket = null;
    reconnectTimer = setTimeout(connectEvents, 3000);
  });
  eventSocket.addEventListener("error", () => eventSocket?.close());
}

function showPanel(panelId) {
  document.querySelectorAll(".panel").forEach((panel) => { panel.hidden = panel.id !== panelId; });
  document.querySelectorAll(".nav-button").forEach((button) => { button.classList.toggle("active", button.dataset.panel === panelId); });
  if (panelId === "users-panel") loadUsers().catch((error) => showNotice(error.message, "error"));
  if (panelId === "graphics-panel") loadAdminGraphics().catch((error) => showNotice(error.message, "error"));
  if (panelId === "proxies-panel") {
    updateNewCertificateBackend();
    loadAdminProxies().catch((error) => showNotice(error.message, "error"));
  }
}

let authMode = "local";

function showLogin(message) {
  document.querySelector("#loading").hidden = true;
  document.querySelector("#app").hidden = true;
  document.querySelector("#main-nav").hidden = true;
  document.querySelector("#account").hidden = true;
  const error = document.querySelector("#login-error");
  error.textContent = message || "";
  error.hidden = !message;
  document.querySelector("#login").hidden = false;
  document.querySelector("#login-username").focus();
}

async function start() {
  try {
    const status = await api("/api/v1/auth/status");
    authMode = status.auth_mode;
    if (!status.authenticated) {
      showLogin("");
      return;
    }
  } catch {
    // An older or differently configured server may not expose the status
    // endpoint; fall back to probing the profile directly.
  }
  try {
    const profile = await api("/api/v1/me");
    currentProfile = profile;
    document.querySelector("#login").hidden = true;
    document.querySelector("#loading").hidden = true;
    document.querySelector("#account-name").textContent = currentProfile.display_name;
    // Local accounts manage their own password; a gateway owns it otherwise.
    document.querySelector("#account-password").hidden = authMode !== "local";
    document.querySelector("#account-logout").hidden = authMode !== "local";
    document.querySelector("#account").hidden = false;
    if (authMode === "local" && currentProfile.role === "admin" && !currentProfile.password_set) {
      document.querySelector("#password-warning").hidden = false;
    }
    document.querySelector("#create-user-form").hidden = authMode !== "local";
    if (!profile.access_granted) {
      document.querySelector("#pending-name").textContent = currentProfile.display_name;
      document.querySelector("#pending-message").textContent = currentProfile.access_message;
      document.querySelector("#access-pending").hidden = false;
      return;
    }
    document.querySelector("#app").hidden = false;
    document.querySelector("#main-nav").hidden = false;
    if (currentProfile.role === "admin") {
      document.querySelector("#users-nav").hidden = false;
      document.querySelector("#graphics-nav").hidden = false;
      document.querySelector("#proxies-nav").hidden = false;
    }
    await refreshOwnershipTools();
    await loadSigningResources();
    await loadDocuments();
    connectEvents();
  } catch (error) {
    if (authMode === "local" && error.code === "authentication_required") {
      showLogin("");
      return;
    }
    document.querySelector("#loading p").textContent = error.message;
  }
}

document.querySelector("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = document.querySelector("#login-error");
  error.hidden = true;
  try {
    await api("/api/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.querySelector("#login-username").value,
        password: document.querySelector("#login-password").value,
      }),
    });
  } catch (failure) {
    error.textContent = failure.message;
    error.hidden = false;
    return;
  }
  window.location.reload();
});

document.querySelector("#account-logout").addEventListener("click", async () => {
  await api("/api/v1/auth/logout", { method: "POST" }).catch(() => null);
  window.location.reload();
});

function openPasswordDialog() {
  const dialog = document.querySelector("#password-dialog");
  document.querySelector("#password-error").hidden = true;
  document.querySelector("#new-password").value = "";
  document.querySelector("#current-password").value = "";
  // There is no current password to confirm during the first-run phase.
  document.querySelector("#current-password-field").hidden = !currentProfile.password_set;
  dialog.showModal();
}

let editingUser = null;

function openUserDialog(user) {
  editingUser = user;
  document.querySelector("#user-error").hidden = true;
  document.querySelector("#edit-username").value = user.username;
  document.querySelector("#edit-display-name").value = user.display_name;
  document.querySelector("#edit-email").value = user.email || "";
  document.querySelector("#edit-password").value = "";
  document.querySelector("#user-dialog").showModal();
}

document.querySelector("#user-cancel").addEventListener("click", () => {
  document.querySelector("#user-dialog").close();
});

document.querySelector("#user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = document.querySelector("#user-error");
  error.hidden = true;
  const password = document.querySelector("#edit-password").value;
  try {
    await api(`/api/v1/admin/users/${editingUser.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.querySelector("#edit-username").value.trim(),
        display_name: document.querySelector("#edit-display-name").value.trim(),
        email: document.querySelector("#edit-email").value.trim(),
      }),
    });
    if (password) {
      await api(`/api/v1/admin/users/${editingUser.id}/password`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ new_password: password }),
      });
    }
  } catch (failure) {
    error.textContent = failure.message;
    error.hidden = false;
    return;
  }
  document.querySelector("#user-dialog").close();
  await loadUsers();
  showNotice("Utente aggiornato.");
});

document.querySelector("#account-password").addEventListener("click", openPasswordDialog);
document.querySelector("#set-password-now").addEventListener("click", openPasswordDialog);
document.querySelector("#password-cancel").addEventListener("click", () => {
  document.querySelector("#password-dialog").close();
});

document.querySelector("#password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = document.querySelector("#password-error");
  error.hidden = true;
  try {
    await api("/api/v1/auth/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        current_password: document.querySelector("#current-password").value,
        new_password: document.querySelector("#new-password").value,
      }),
    });
  } catch (failure) {
    error.textContent = failure.message;
    error.hidden = false;
    return;
  }
  document.querySelector("#password-dialog").close();
  document.querySelector("#password-warning").hidden = true;
  currentProfile.password_set = true;
  showNotice("Password aggiornata.");
});

document.querySelector("#create-user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  try {
    await api("/api/v1/admin/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: form.username.value.trim(),
        display_name: form.display_name.value.trim(),
        email: form.email.value.trim() || null,
        role: form.role.value,
        password: form.password.value,
      }),
    });
    form.reset();
    await loadUsers();
    await refreshOwnershipTools();
    refreshDocuments();
    showNotice("Utente creato.");
  } catch (error) {
    showNotice(error.message, "error");
  }
});

document.querySelector("#file-input").addEventListener("change", (event) => {
  const [file] = event.target.files;
  if (file) uploadDocument(file);
  event.target.value = "";
});
document.querySelectorAll(".nav-button").forEach((button) => button.addEventListener("click", () => showPanel(button.dataset.panel)));
document.querySelector("#refresh-users").addEventListener("click", () => refreshUsers());

const searchDocuments = debounce((term) => {
  documentFilters.search = term;
  documentFilters.offset = 0;
  refreshDocuments();
});
document.querySelector("#documents-search").addEventListener("input", (event) => searchDocuments(event.target.value.trim()));

const searchUsers = debounce((term) => {
  userFilters.search = term;
  userFilters.offset = 0;
  refreshUsers();
});
document.querySelector("#users-search").addEventListener("input", (event) => searchUsers(event.target.value.trim()));

const searchOwnerCandidates = debounce((term) => {
  ownerOptions.term = term;
  ownerOptions.active = -1;
  loadOwnerOptions();
});
const ownerSearch = document.querySelector("#owner-search");
ownerSearch.addEventListener("focus", () => openOwnerOptions());
ownerSearch.addEventListener("input", (event) => {
  openOwnerOptions();
  searchOwnerCandidates(event.target.value.trim());
});
ownerSearch.addEventListener("keydown", (event) => {
  if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    openOwnerOptions();
    moveOwnerHighlight(event.key === "ArrowDown" ? 1 : -1);
  } else if (event.key === "Enter") {
    event.preventDefault();
    const user = ownerOptions.items[ownerOptions.active];
    if (user) toggleOwnerFilter(user);
  } else if (event.key === "Escape") {
    closeOwnerOptions();
  } else if (event.key === "Backspace" && !event.target.value && documentFilters.owners.length) {
    toggleOwnerFilter(documentFilters.owners[documentFilters.owners.length - 1]);
  }
});
ownerSearch.addEventListener("blur", () => closeOwnerOptions());
// The list is a page at a time: reaching its end asks for the next one.
document.querySelector("#owner-options").addEventListener("scroll", (event) => {
  const list = event.target;
  if (list.scrollTop + list.clientHeight >= list.scrollHeight - 24) loadOwnerOptions({ append: true });
});
document.querySelector("#owner-clear").addEventListener("click", () => {
  ownerSearch.value = "";
  ownerOptions.term = "";
  clearOwnerFilter();
  loadOwnerOptions();
  ownerSearch.focus();
});

const searchDialogOwners = debounce(() => loadOwnerCandidates());
const ownerDialogSearch = document.querySelector("#owner-dialog-search");
ownerDialogSearch.addEventListener("input", () => searchDialogOwners());
// The field lives inside the dialog's form, where Enter would mean "assign".
ownerDialogSearch.addEventListener("keydown", (event) => {
  if (event.key === "Enter") event.preventDefault();
});
document.querySelector("#create-graphic-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  try {
    await api("/api/v1/admin/graphic-signatures", { method: "POST", body: new FormData(form) });
    form.reset();
    showNotice("Firma grafica creata.");
    await Promise.all([loadAdminGraphics(), loadSigningResources()]);
    await loadDocuments();
  } catch (error) {
    showNotice(error.message, "error");
  }
});
document.querySelector("#create-proxy-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  const data = new FormData(form);
  const backend = data.get("backend");
  const body = { name: data.get("name"), backend };
  if (backend === "local") {
    const selectedIndex = Number(document.querySelector("#new-pkcs11-certificate").value);
    const selected = discoveredLocalCertificates[selectedIndex];
    if (!selected) {
      showNotice("Rileva e seleziona un certificato PKCS#11.", "error");
      return;
    }
    body.pkcs11_library_path = selectedLocalLibraryPath();
    body.pkcs11_token_label = selected.token_label;
    body.pkcs11_certificate_label = selected.certificate_label;
    body.save_pin = document.querySelector("#new-save-pin").checked;
    if (body.save_pin) body.pin = document.querySelector("#new-pkcs11-pin").value;
  } else {
    body.base_url = data.get("base_url");
  }
  try {
    await api("/api/v1/admin/signing-proxies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    form.reset();
    clearLocalCertificateDiscovery();
    document.querySelector("#new-pin-field").hidden = true;
    document.querySelector("#new-pkcs11-pin").required = false;
    document.querySelector("#new-pkcs11-pin").value = "";
    updatePinEncryptionWarning();
    updateNewCertificateBackend();
    showNotice("Certificato aggiunto.");
    await Promise.all([loadAdminProxies(), loadSigningResources()]);
  } catch (error) {
    showNotice(error.message, "error");
  }
});
function updateNewCertificateBackend() {
  const local = document.querySelector("#new-certificate-backend").value === "local";
  document.querySelector("#new-proxy-url-field").hidden = local;
  document.querySelector("#new-proxy-url").required = !local;
  document.querySelector("#new-local-certificate-fields").hidden = !local;
  document.querySelector("#new-pkcs11-library-choice").required = local;
  if (local) loadKnownPkcs11Libraries().catch((error) => showNotice(error.message, "error"));
}
document.querySelector("#new-certificate-backend").addEventListener("change", updateNewCertificateBackend);
document.querySelector("#new-save-pin").addEventListener("change", (event) => {
  document.querySelector("#new-pin-field").hidden = !event.target.checked;
  document.querySelector("#new-pkcs11-pin").required = event.target.checked;
  updatePinEncryptionWarning();
});
document.querySelector("#new-pkcs11-library-choice").addEventListener("change", () => {
  clearTimeout(localLibraryDebounceTimer);
  updateLocalLibraryChoice();
  clearLocalCertificateDiscovery();
  if (selectedLocalLibraryPath()) discoverLocalCertificates({ announce: false }).catch((error) => showNotice(error.message, "error"));
});
document.querySelector("#new-pkcs11-library").addEventListener("input", () => {
  clearTimeout(localLibraryDebounceTimer);
  clearLocalCertificateDiscovery("Attendo un percorso valido…");
  localLibraryDebounceTimer = setTimeout(() => {
    discoverLocalCertificates({ announce: false, checkExists: true }).catch((error) => showNotice(error.message, "error"));
  }, 600);
});
document.querySelector("#discover-pkcs11").addEventListener("click", () => discoverLocalCertificates({ checkExists: true }));
document.querySelector("#signature-mode").addEventListener("change", updateSignMode);
document.querySelector("#cades-strategy").addEventListener("change", updateSignSummary);
document.querySelector("#xades-packaging").addEventListener("change", updateSignSummary);
document.querySelector("#signing-proxy").addEventListener("change", updateSignMode);
document.querySelector("#pades-graphic").addEventListener("change", updateSignMode);
document.querySelector("#add-placement").addEventListener("click", addPlacement);
document.querySelector("#remove-placement").addEventListener("click", removeSelectedPlacement);
document.querySelector("#pdf-stage").addEventListener("pdf-page-rendered", renderPlacementLayer);
document.querySelector("#sign-form").addEventListener("submit", submitSignature);
document.querySelector("#cancel-sign").addEventListener("click", () => document.querySelector("#sign-dialog").close());
document.querySelector("#sign-dialog").addEventListener("close", () => {
  signingDocument = null;
  activeJobId = null;
  clearTimeout(jobPollTimer);
  pdfPreviewToken += 1;
  if (pdfPreviewPromise) pdfPreviewPromise.then((preview) => preview.closePdf());
});
document.querySelector("#owner-dialog").addEventListener("close", (event) => {
  if (event.target.returnValue === "confirm") changeSelectedOwner();
});

start();
