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

					respondJSON(sendResponseCallback, 200, {
						requested: itemKeys.length,
						processed: items.length,
						skipped: skipped.length,
						details: skipped,
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
