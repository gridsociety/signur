import * as pdfjsLib from "/static/vendor/pdfjs/build/pdf.mjs";

pdfjsLib.GlobalWorkerOptions.workerSrc = "/static/vendor/pdfjs/build/pdf.worker.mjs";

const canvas = document.querySelector("#pdf-canvas");
const stage = document.querySelector("#pdf-stage");
const scrollArea = document.querySelector("#pdf-scroll");
const pageStatus = document.querySelector("#page-status");
const zoomStatus = document.querySelector("#zoom-status");
const errorBox = document.querySelector("#preview-error");
const previousButton = document.querySelector("#previous-page");
const nextButton = document.querySelector("#next-page");
const zoomOutButton = document.querySelector("#zoom-out");
const zoomInButton = document.querySelector("#zoom-in");

let pdfDocument = null;
let loadingTask = null;
let renderTask = null;
let pageNumber = 1;
let zoom = 1;
let generation = 0;

function dispatchRendered() {
  stage.dispatchEvent(new CustomEvent("pdf-page-rendered", { detail: { pageNumber } }));
}

async function renderPage() {
  if (!pdfDocument) return;
  const ownGeneration = generation;
  const page = await pdfDocument.getPage(pageNumber);
  if (ownGeneration !== generation) return;
  const naturalViewport = page.getViewport({ scale: 1 });
  const availableWidth = Math.max(280, scrollArea.clientWidth - 32);
  const fitScale = availableWidth / naturalViewport.width;
  const viewport = page.getViewport({ scale: fitScale * zoom });
  const outputScale = window.devicePixelRatio || 1;
  canvas.width = Math.floor(viewport.width * outputScale);
  canvas.height = Math.floor(viewport.height * outputScale);
  canvas.style.width = `${Math.floor(viewport.width)}px`;
  canvas.style.height = `${Math.floor(viewport.height)}px`;
  stage.style.width = canvas.style.width;
  stage.style.height = canvas.style.height;
  if (renderTask) renderTask.cancel();
  renderTask = page.render({
    canvasContext: canvas.getContext("2d"),
    viewport,
    transform: outputScale === 1 ? null : [outputScale, 0, 0, outputScale, 0, 0],
  });
  try {
    await renderTask.promise;
  } catch (error) {
    if (error?.name !== "RenderingCancelledException") throw error;
    return;
  }
  pageStatus.textContent = `Pagina ${pageNumber} di ${pdfDocument.numPages}`;
  stage.dataset.pageNumber = String(pageNumber);
  zoomStatus.textContent = `${Math.round(zoom * 100)}%`;
  previousButton.disabled = pageNumber <= 1;
  nextButton.disabled = pageNumber >= pdfDocument.numPages;
  zoomOutButton.disabled = zoom <= 0.75;
  zoomInButton.disabled = zoom >= 3;
  dispatchRendered();
}

export async function openPdf(url) {
  await closePdf();
  generation += 1;
  const ownGeneration = generation;
  pageNumber = 1;
  zoom = 1;
  errorBox.hidden = true;
  stage.hidden = false;
  pageStatus.textContent = "Caricamento…";
  // Keep our own handle: a newer openPdf may replace the shared one while we wait.
  const task = pdfjsLib.getDocument({
    url,
    cMapUrl: "/static/vendor/pdfjs/web/cmaps/",
    cMapPacked: true,
    standardFontDataUrl: "/static/vendor/pdfjs/web/standard_fonts/",
    wasmUrl: "/static/vendor/pdfjs/web/wasm/",
    iccUrl: "/static/vendor/pdfjs/web/iccs/",
  });
  loadingTask = task;
  try {
    const loaded = await task.promise;
    if (ownGeneration !== generation) {
      await task.destroy();
      return;
    }
    pdfDocument = loaded;
    await renderPage();
  } catch (error) {
    if (ownGeneration !== generation) return;
    console.error("PDF preview failed", error);
    pageStatus.textContent = "Anteprima non disponibile";
    stage.hidden = true;
    errorBox.hidden = false;
  }
}

export async function closePdf() {
  generation += 1;
  if (renderTask) {
    renderTask.cancel();
    renderTask = null;
  }
  pdfDocument = null;
  canvas.width = 0;
  canvas.height = 0;
  if (loadingTask) {
    // Only the loading task can release the document and stop its worker: the
    // document itself offers cleanup(), never destroy().
    const task = loadingTask;
    loadingTask = null;
    await task.destroy();
  }
}

export function currentPageNumber() {
  return pageNumber;
}

export async function showPage(number) {
  if (!pdfDocument || number < 1 || number > pdfDocument.numPages) return;
  pageNumber = number;
  await renderPage();
}

previousButton.addEventListener("click", async () => {
  if (pageNumber <= 1) return;
  pageNumber -= 1;
  await renderPage();
});
nextButton.addEventListener("click", async () => {
  if (!pdfDocument || pageNumber >= pdfDocument.numPages) return;
  pageNumber += 1;
  await renderPage();
});
zoomOutButton.addEventListener("click", async () => {
  zoom = Math.max(0.75, zoom - 0.25);
  await renderPage();
});
zoomInButton.addEventListener("click", async () => {
  zoom = Math.min(3, zoom + 0.25);
  await renderPage();
});
