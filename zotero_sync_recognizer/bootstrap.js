var ENDPOINTS = [];
var STATUS_MENU_ID = "zotero-sync-recognizer-status-menuitem";
var STATUS_PANEL_ID = "zotero-sync-recognizer-status-panel";
var STATUS_PANELS = new Map();
var STATUS_POLL_INTERVAL_MS = 2000;

function log(msg) {
	Zotero.debug("Zotero Sync Recognizer: " + msg);
}

function respondJSON(sendResponseCallback, status, payload) {
	sendResponseCallback(status, "application/json", JSON.stringify(payload));
}

async function getItemByLibraryAndKey(libraryID, key) {
	let item;
	if (Zotero.Items.getByLibraryAndKeyAsync) {
		item = await Zotero.Items.getByLibraryAndKeyAsync(libraryID, key);
	}
	else if (Zotero.Items.getByLibraryAndKey) {
		item = Zotero.Items.getByLibraryAndKey(libraryID, key);
	}
	else {
		throw new Error("Zotero.Items.getByLibraryAndKeyAsync indisponível");
	}
	if (item && Zotero.Items.getAsync) {
		return Zotero.Items.getAsync(item.id);
	}
	return item;
}

async function getItemByID(itemID) {
	if (!itemID) {
		return null;
	}
	if (Zotero.Items.getAsync) {
		return Zotero.Items.getAsync(itemID);
	}
	if (Zotero.Items.get) {
		return Zotero.Items.get(itemID);
	}
	throw new Error("Zotero.Items.getAsync indisponível");
}

async function getCollectionByLibraryAndKey(libraryID, key) {
	if (!key) {
		return null;
	}
	if (Zotero.Collections.getByLibraryAndKeyAsync) {
		return Zotero.Collections.getByLibraryAndKeyAsync(libraryID, key);
	}
	if (Zotero.Collections.getByLibraryAndKey) {
		return Zotero.Collections.getByLibraryAndKey(libraryID, key);
	}
	throw new Error("Zotero.Collections.getByLibraryAndKeyAsync indisponível");
}



function parsePayload(postData) {
	if (!postData) {
		return {};
	}
	if (typeof postData == "string") {
		return JSON.parse(postData);
	}
	if (postData.data && typeof postData.data == "string") {
		return JSON.parse(postData.data);
	}
	return postData;
}

function stripCopyMarkers(value) {
	let cleaned = (value || "").trim();
	let previous = null;
	while (cleaned && cleaned !== previous) {
		previous = cleaned;
		cleaned = cleaned.replace(/^\s*(?:c[oó]pia\s+de|copy\s+of)\s+/i, "").trim();
	}
	cleaned = cleaned.replace(/(?:\s*\(\d+\)|\s+1)\s*$/i, "").trim();
	return cleaned.replace(/\s+/g, " ").trim();
}

function fallbackParentTitleFromAttachment(item) {
	let title = (item.getField && item.getField("title")) || "";
	let filename = item.attachmentFilename || "";
	let source = title && title !== "PDF" ? title : filename;
	if (!source) {
		return "";
	}
	source = stripCopyMarkers(source);
	source = source.replace(/\.pdf$/i, "");
	return source.trim();
}

async function createFallbackParent(item) {
	let title = fallbackParentTitleFromAttachment(item);
	if (!title) {
		return null;
	}
	let parentItem = new Zotero.Item("document");
	parentItem.libraryID = item.libraryID;
	parentItem.setField("title", title);
	await parentItem.saveTx();

	let collections = item.getCollections();
	if (collections.length) {
		for (let collectionID of collections) {
			parentItem.addToCollection(collectionID);
		}
		await parentItem.saveTx();
	}
	item.parentID = parentItem.id;
	await item.saveTx();
	return parentItem;
}

async function revealItems(items) {
	if (!items.length) {
		return;
	}
	let win = Zotero.getMainWindow && Zotero.getMainWindow();
	if (!win || !win.ZoteroPane) {
		return;
	}
	try {
		if (typeof win.ZoteroPane.selectItems == "function") {
			await win.ZoteroPane.selectItems(items.map(item => item.id));
			return;
		}
		if (typeof win.ZoteroPane.selectItem == "function") {
			await win.ZoteroPane.selectItem(items[0].id);
		}
	}
	catch (e) {
		Zotero.logError(e);
	}
}

async function postRecognizeFallback(libraryID, attachments) {
	let createdParents = [];
	for (let item of attachments) {
		let latest = await getItemByLibraryAndKey(libraryID, item.key);
		if (!latest) {
			continue;
		}
		if (!latest.isTopLevelItem() || !latest.isAttachment()) {
			let parentItem = await getItemByID(latest.parentItemID || latest.parentID);
			if (parentItem) {
				createdParents.push({
					attachmentKey: item.key,
					parentKey: parentItem.key,
					parentTitle: parentItem.getField("title"),
					source: "recognized",
				});
			}
			continue;
		}
		let parentItem = await createFallbackParent(latest);
		if (!parentItem) {
			continue;
		}
		createdParents.push({
			attachmentKey: item.key,
			parentKey: parentItem.key,
			parentTitle: parentItem.getField("title"),
			source: "fallback",
		});
	}
	if (createdParents.length) {
		let parentItems = [];
		for (let parent of createdParents) {
			let item = await getItemByLibraryAndKey(libraryID, parent.parentKey);
			if (item) {
				parentItems.push(item);
			}
		}
		await revealItems(parentItems);
	}
	return createdParents;
}

async function importAttachment(payload) {
	let libraryID = payload.libraryID || Zotero.Libraries.userLibraryID;
	let filePath = payload.filePath;
	let parentKey = payload.parentKey || "";
	let collectionKey = payload.collectionKey || "";
	let title = payload.title;
	let autoRecognize = payload.autoRecognize !== false;
	if (!filePath) {
		throw new Error("filePath é obrigatório");
	}

	let options = {
		file: filePath,
		libraryID,
	};
	if (title) {
		options.title = title;
	}
	let parentItem = null;
	if (parentKey) {
		parentItem = await getItemByLibraryAndKey(libraryID, parentKey);
		if (!parentItem) {
			throw new Error("parentKey não encontrado");
		}
		options.parentItemID = parentItem.id;
	}
	else if (collectionKey) {
		let collection = await getCollectionByLibraryAndKey(libraryID, collectionKey);
		if (!collection) {
			throw new Error(`Collection ${collectionKey} not found for item ${libraryID}/${parentKey || 'null'}`);
		}
		options.collections = [collection.id];
	}

	let attachment = await Zotero.Attachments.importFromFile(options);
	let result = {
		attachmentKey: attachment.key,
		attachmentTitle: attachment.getField("title"),
		attachmentFilename: attachment.attachmentFilename || "",
		parentKey: parentItem ? parentItem.key : "",
		parentTitle: parentItem ? parentItem.getField("title") : "",
		fallbackParents: [],
		fallbackPending: false,
	};

	if (!parentItem && !autoRecognize) {
		// Em --headless, consultar o item imediatamente após importFromFile pode
		// bloquear a transação do Zotero. A próxima sincronização o reconhece
		// quando o item já estiver totalmente materializado.
		log("Importação headless concluída; pai fallback pendente: " + attachment.key);
		result.fallbackPending = true;
	}
	else if (!parentItem && Zotero.RecognizeDocument.canRecognize(attachment)) {
		await Zotero.RecognizeDocument.recognizeItems([attachment]);
		result.fallbackParents = await postRecognizeFallback(libraryID, [attachment]);
		if (result.fallbackParents.length) {
			let latestAttachment = await getItemByLibraryAndKey(libraryID, attachment.key);
			result.attachmentTitle = latestAttachment ? latestAttachment.getField("title") : result.attachmentTitle;
			result.attachmentFilename = latestAttachment ? latestAttachment.attachmentFilename : result.attachmentFilename;
			result.parentKey = result.fallbackParents[0].parentKey;
			result.parentTitle = result.fallbackParents[0].parentTitle;
		}
	}

	return result;
}

async function discardStandaloneAttachment(payload) {
	let libraryID = payload.libraryID || Zotero.Libraries.userLibraryID;
	let item = await getItemByLibraryAndKey(libraryID, payload.itemKey || "");
	if (!item || !item.isAttachment() || !item.isTopLevelItem()) {
		throw new Error("Somente anexos standalone podem ser descartados");
	}
	await item.eraseTx();
	return { discarded: item.key };
}

function createXULElement(doc, name) {
	return doc.createXULElement ? doc.createXULElement(name) : doc.createElement(name);
}

function getStatusSnapshotPath() {
	let home = Services.dirsvc.get("Home", Ci.nsIFile).path;
	return home + "/.cache/zotero_sync_webdav/sync_status.json";
}

async function readSyncStatusSnapshot() {
	try {
		let raw = await Zotero.File.getContentsAsync(getStatusSnapshotPath());
		let snapshot = JSON.parse(raw);
		if (!snapshot || typeof snapshot != "object") {
			throw new Error("O arquivo de status não contém um objeto JSON.");
		}
		return snapshot;
	}
	catch (e) {
		return {
			state: "unavailable",
			message: e && e.message ? e.message : String(e),
		};
	}
}

function statusTitle(state) {
	switch (state) {
		case "running":
			return "Sincronização em andamento";
		case "completed":
			return "Última sincronização concluída";
		case "failed":
			return "Sincronização interrompida";
		default:
			return "Status indisponível";
	}
}

function formatTimestamp(value) {
	if (!value) {
		return "Sem execução concluída registrada.";
	}
	let timestamp = new Date(value);
	return isNaN(timestamp.getTime()) ? value : timestamp.toLocaleString();
}

function renderStatusPanel(panelState, snapshot) {
	let unavailable = snapshot.state == "unavailable";
	let progress = snapshot.progress || {};
	let counts = snapshot.counts || {};
	let processed = Number(progress.processed || 0);
	let total = Number(progress.total || 0);
	let percent = total > 0 ? Math.min(100, Math.round((processed / total) * 100)) : 0;

	panelState.title.value = statusTitle(snapshot.state);
	panelState.stage.value = unavailable
		? "O sincronizador ainda não publicou um status local."
		: (snapshot.stage || "Aguardando próxima atualização.");
	panelState.progress.hidden = unavailable;
	panelState.progress.value = percent;
	panelState.progressLabel.value = unavailable
		? "Abra o log se o sincronizador não estiver em execução."
		: (total > 0 ? "PDFs processados: " + processed + " de " + total + " (" + percent + "%)" : "Nenhum PDF em processamento.");
	panelState.counts.value = unavailable
		? "Motivo: " + (snapshot.message || "snapshot ausente")
		: "Erros: " + Number(counts.errors || 0)
			+ "  |  Bloqueios de duplicata: " + Number(counts.duplicateBlocks || 0)
			+ "  |  Revisões: " + Number(counts.duplicateReview || 0);
	panelState.details.value = unavailable
		? "O painel é somente leitura e nunca inicia uma sync."
		: (snapshot.lastError
			? "Último erro: " + snapshot.lastError
			: "Adicionados: " + Number(counts.added || 0)
				+ "  |  Existentes: " + Number(counts.existing || 0)
				+ "  |  Grupos duplicados: " + Number(counts.duplicateGroups || 0));
	panelState.updated.value = "Atualizado: " + formatTimestamp(snapshot.updatedAt || snapshot.completedAt);
}

async function refreshStatusPanel(panelState) {
	if (panelState.refreshing) {
		return;
	}
	panelState.refreshing = true;
	try {
		renderStatusPanel(panelState, await readSyncStatusSnapshot());
	}
	finally {
		panelState.refreshing = false;
	}
}

function stopStatusPolling(panelState) {
	if (panelState.timer) {
		panelState.window.clearInterval(panelState.timer);
		panelState.timer = null;
	}
}

function startStatusPolling(panelState) {
	stopStatusPolling(panelState);
	refreshStatusPanel(panelState);
	panelState.timer = panelState.window.setInterval(
		() => refreshStatusPanel(panelState),
		STATUS_POLL_INTERVAL_MS
	);
}

function createStatusPanel(win, anchor) {
	let doc = win.document;
	let panel = createXULElement(doc, "panel");
	panel.id = STATUS_PANEL_ID;
	panel.setAttribute("type", "arrow");
	panel.setAttribute("noautohide", "true");

	let box = createXULElement(doc, "vbox");
	box.style.padding = "14px";
	box.style.width = "390px";
	box.style.gap = "8px";
	panel.appendChild(box);

	let title = createXULElement(doc, "label");
	title.style.fontWeight = "600";
	title.style.fontSize = "1.1em";
	box.appendChild(title);

	let stage = createXULElement(doc, "label");
	stage.setAttribute("crop", "end");
	box.appendChild(stage);

	let progress = createXULElement(doc, "progressmeter");
	progress.setAttribute("mode", "determined");
	box.appendChild(progress);

	let progressLabel = createXULElement(doc, "label");
	box.appendChild(progressLabel);

	let separator = createXULElement(doc, "separator");
	separator.setAttribute("class", "thin");
	box.appendChild(separator);

	let counts = createXULElement(doc, "label");
	counts.setAttribute("crop", "end");
	box.appendChild(counts);

	let details = createXULElement(doc, "label");
	details.setAttribute("crop", "end");
	details.setAttribute("multiline", "true");
	box.appendChild(details);

	let updated = createXULElement(doc, "label");
	updated.style.opacity = "0.72";
	box.appendChild(updated);

	let closeButton = createXULElement(doc, "button");
	closeButton.setAttribute("label", "Fechar");
	box.appendChild(closeButton);

	let panelState = {
		window: win,
		panel,
		anchor,
		title,
		stage,
		progress,
		progressLabel,
		counts,
		details,
		updated,
		timer: null,
		refreshing: false,
	};
	closeButton.addEventListener("command", () => panel.hidePopup());
	panel.addEventListener("popupshown", () => startStatusPolling(panelState));
	panel.addEventListener("popuphidden", () => stopStatusPolling(panelState));
	doc.documentElement.appendChild(panel);
	STATUS_PANELS.set(win, panelState);
	return panelState;
}

function openStatusPanel(win, anchor) {
	let panelState = STATUS_PANELS.get(win) || createStatusPanel(win, anchor);
	panelState.anchor = anchor;
	panelState.panel.openPopup(anchor, "after_end", 0, 0, false, false);
}

function installStatusMenu(win) {
	let doc = win.document;
	if (doc.getElementById(STATUS_MENU_ID)) {
		return;
	}
	let toolsPopup = doc.getElementById("menu_ToolsPopup");
	if (!toolsPopup) {
		log("menu Ferramentas não encontrado; painel de status não instalado.");
		return;
	}
	let item = createXULElement(doc, "menuitem");
	item.id = STATUS_MENU_ID;
	item.setAttribute("label", "Status da sincronização Zotero");
	item.addEventListener("command", () => openStatusPanel(win, item));
	toolsPopup.appendChild(item);
}

function removeStatusUI(win) {
	let panelState = STATUS_PANELS.get(win);
	if (panelState) {
		stopStatusPolling(panelState);
		panelState.panel.remove();
		STATUS_PANELS.delete(win);
	}
	let menuItem = win.document.getElementById(STATUS_MENU_ID);
	if (menuItem) {
		menuItem.remove();
	}
}

function installEndpoints() {
	var pingPath = "/zoteroSyncRecognize/ping";
	var recognizePath = "/zoteroSyncRecognize/recognize";
	var importPath = "/zoteroSyncRecognize/import";
	var discardPath = "/zoteroSyncRecognize/discard";

	var PingEndpoint = Zotero.Server.Endpoints[pingPath] = function () {};
	PingEndpoint.prototype = {
		supportedMethods: ["GET", "POST"],
		init: function (_data, sendResponseCallback) {
			respondJSON(sendResponseCallback, 200, { ok: true, plugin: "zotero-sync-recognizer" });
		}
	};

	var RecognizeEndpoint = Zotero.Server.Endpoints[recognizePath] = function () {};
	RecognizeEndpoint.prototype = {
		supportedMethods: ["POST"],
		init: function (postData, sendResponseCallback) {
			(async () => {
				try {
					let payload = parsePayload(postData);
					let libraryID = payload.libraryID || Zotero.Libraries.userLibraryID;
					let autoRecognize = payload.autoRecognize !== false;
					let itemKeys = Array.isArray(payload.itemKeys) ? payload.itemKeys : [];
					let items = [];
					let skipped = [];

					for (let key of itemKeys) {
						let item = await getItemByLibraryAndKey(libraryID, key);
						if (!item) {
							skipped.push({ key, reason: "not_found" });
							continue;
						}
						if (!Zotero.RecognizeDocument.canRecognize(item)) {
							skipped.push({ key, reason: "not_recognizable" });
							continue;
						}
						items.push(item);
					}

					if (autoRecognize && items.length) {
						await Zotero.RecognizeDocument.recognizeItems(items);
					}

					let createdParents = await postRecognizeFallback(libraryID, items);
					respondJSON(sendResponseCallback, 200, {
						requested: itemKeys.length,
						processed: items.length,
						fallbackParents: createdParents.length,
						skipped: skipped.length,
						details: skipped,
						createdParents,
					});
				}
				catch (e) {
					Zotero.logError(e);
					respondJSON(sendResponseCallback, 500, {
						error: e && e.message ? e.message : String(e),
					});
				}
			})();
		}
	};

	var ImportEndpoint = Zotero.Server.Endpoints[importPath] = function () {};
	ImportEndpoint.prototype = {
		supportedMethods: ["POST"],
		init: function (postData, sendResponseCallback) {
			(async () => {
				try {
					let payload = parsePayload(postData);
					let result = await importAttachment(payload);
					respondJSON(sendResponseCallback, 200, result);
				}
				catch (e) {
					Zotero.logError(e);
					respondJSON(sendResponseCallback, 500, {
						error: e && e.message ? e.message : String(e),
					});
				}
			})();
		}
	};

	var DiscardEndpoint = Zotero.Server.Endpoints[discardPath] = function () {};
	DiscardEndpoint.prototype = {
		supportedMethods: ["POST"],
		init: function (postData, sendResponseCallback) {
			(async () => {
				try {
					let result = await discardStandaloneAttachment(parsePayload(postData));
					respondJSON(sendResponseCallback, 200, result);
				}
				catch (e) {
					Zotero.logError(e);
					respondJSON(sendResponseCallback, 500, {
						error: e && e.message ? e.message : String(e),
					});
				}
			})();
		}
	};

	ENDPOINTS = [pingPath, recognizePath, importPath, discardPath];
}

function removeEndpoints() {
	for (let path of ENDPOINTS) {
		delete Zotero.Server.Endpoints[path];
	}
	ENDPOINTS = [];
}

function install() {}

function startup() {
	installEndpoints();
	for (let win of Zotero.getMainWindows()) {
		installStatusMenu(win);
	}
	log("started");
}

function onMainWindowLoad({ window }) {
	installStatusMenu(window);
}

function onMainWindowUnload({ window }) {
	removeStatusUI(window);
}

function shutdown() {
	for (let win of Zotero.getMainWindows()) {
		removeStatusUI(win);
	}
	removeEndpoints();
	log("stopped");
}

function uninstall() {}
