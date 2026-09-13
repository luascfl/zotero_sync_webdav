/* global Ci, Services, Zotero */
"use strict";

const POLL_INTERVAL_MS = 2000;
let pollTimer = null;

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
	catch (error) {
		return {
			state: "unavailable",
			message: error && error.message ? error.message : String(error),
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

function renderStatus(snapshot) {
	let unavailable = snapshot.state == "unavailable";
	let progress = snapshot.progress || {};
	let counts = snapshot.counts || {};
	let processed = Number(progress.processed || 0);
	let total = Number(progress.total || 0);
	let percent = total > 0 ? Math.min(100, Math.round((processed / total) * 100)) : 0;

	document.getElementById("title").textContent = statusTitle(snapshot.state);
	document.getElementById("stage").textContent = unavailable
		? "O sincronizador ainda não publicou um status local."
		: (snapshot.stage || "Aguardando próxima atualização.");
	let progressElement = document.getElementById("progress");
	progressElement.hidden = unavailable;
	progressElement.value = percent;
	document.getElementById("progress-label").textContent = unavailable
		? "Abra o log se o sincronizador não estiver em execução."
		: (total > 0 ? "PDFs processados: " + processed + " de " + total + " (" + percent + "%)" : "Nenhum PDF em processamento.");
	document.getElementById("counts").textContent = unavailable
		? "Motivo: " + (snapshot.message || "snapshot ausente")
		: "Erros: " + Number(counts.errors || 0)
			+ "  |  Bloqueios de duplicata: " + Number(counts.duplicateBlocks || 0)
			+ "  |  Revisões: " + Number(counts.duplicateReview || 0);
	document.getElementById("details").textContent = unavailable
		? "Esta janela é somente leitura e nunca inicia uma sincronização."
		: (snapshot.lastError
			? "Último erro: " + snapshot.lastError
			: "Adicionados: " + Number(counts.added || 0)
				+ "  |  Existentes: " + Number(counts.existing || 0)
				+ "  |  Grupos duplicados: " + Number(counts.duplicateGroups || 0));
	document.getElementById("updated").textContent = "Atualizado: " + formatTimestamp(snapshot.updatedAt || snapshot.completedAt);
}

async function refreshStatus() {
	renderStatus(await readSyncStatusSnapshot());
}

window.addEventListener("load", () => {
	document.getElementById("close").addEventListener("click", () => window.close());
	refreshStatus();
	pollTimer = window.setInterval(refreshStatus, POLL_INTERVAL_MS);
});

window.addEventListener("unload", () => {
	if (pollTimer) {
		window.clearInterval(pollTimer);
		pollTimer = null;
	}
});
