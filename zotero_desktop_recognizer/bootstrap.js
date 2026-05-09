var ENDPOINTS = [];

function log(msg) {
	Zotero.debug("Zotero Sync Recognizer: " + msg);
}

function respondJSON(sendResponseCallback, status, payload) {
	sendResponseCallback(status, "application/json", JSON.stringify(payload));
}

async function getItemByLibraryAndKey(libraryID, key) {
	if (Zotero.Items.getByLibraryAndKeyAsync) {
		return Zotero.Items.getByLibraryAndKeyAsync(libraryID, key);
	}
	if (Zotero.Items.getByLibraryAndKey) {
		return Zotero.Items.getByLibraryAndKey(libraryID, key);
	}
	throw new Error("Zotero.Items.getByLibraryAndKeyAsync indisponível");
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
	await Zotero.DB.executeTransaction(async function () {
		if (collections.length) {
			for (let collectionID of collections) {
				parentItem.addToCollection(collectionID);
			}
			await parentItem.save();
		}
		item.parentID = parentItem.id;
		await item.save();
	});
	return parentItem;
}

async function revealCreatedParents(parentItems) {
	if (!parentItems.length) {
		return;
	}
	let win = Zotero.getMainWindow && Zotero.getMainWindow();
	if (!win || !win.ZoteroPane) {
		return;
	}
	try {
		if (typeof win.ZoteroPane.selectItems == "function") {
			await win.ZoteroPane.selectItems(parentItems.map(item => item.id));
			return;
		}
		if (typeof win.ZoteroPane.selectItem == "function") {
			await win.ZoteroPane.selectItem(parentItems[0].id);
		}
	}
	catch (e) {
		Zotero.logError(e);
	}
}

function installEndpoints() {
	var pingPath = "/zoteroSyncRecognize/ping";
	var recognizePath = "/zoteroSyncRecognize/recognize";

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
					let itemKeys = Array.isArray(payload.itemKeys) ? payload.itemKeys : [];
					let items = [];
					let skipped = [];
					let createdParents = [];

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

					if (items.length) {
						await Zotero.RecognizeDocument.recognizeItems(items);
					}

					for (let item of items) {
						let latest = await getItemByLibraryAndKey(libraryID, item.key);
						if (!latest) {
							skipped.push({ key: item.key, reason: "not_found_after_recognize" });
							continue;
						}
						if (!latest.isTopLevelItem() || !latest.isAttachment()) {
							continue;
						}
						let parentItem = await createFallbackParent(latest);
						if (!parentItem) {
							skipped.push({ key: item.key, reason: "fallback_parent_failed" });
							continue;
						}
						createdParents.push({
							attachmentKey: item.key,
							parentKey: parentItem.key,
							parentTitle: parentItem.getField("title"),
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
						await revealCreatedParents(parentItems);
					}

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

	ENDPOINTS = [pingPath, recognizePath];
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
	log("started");
}

function shutdown() {
	removeEndpoints();
	log("stopped");
}

function uninstall() {}
