(function () {
  function ensureScanInfo(runningText) {
    var scanInfo = document.getElementById("scan-info");
    if (scanInfo) return;

    var scanDiv = document.createElement("div");
    scanDiv.className = "alert alert-info d-flex align-items-center mb-3";
    scanDiv.id = "scan-info";
    scanDiv.innerHTML =
      "<strong>" + (runningText || "Scanning…") + "</strong>" +
      '<div class="spinner-border text-primary ml-auto" role="status" aria-hidden="true"></div>';

    var cardBody = document.querySelector(".card-body");
    if (cardBody) {
      cardBody.insertBefore(scanDiv, cardBody.firstChild);
    }
  }

  function removeScanInfoAndReload(delayMs) {
    var scanInfo = document.getElementById("scan-info");
    if (scanInfo) scanInfo.remove();

    window.setTimeout(function () {
      window.location.reload();
    }, delayMs);
  }

  function startScanStatusPolling() {
    var poller = document.getElementById("scan-status-poller");
    if (!poller) return;

    var url = poller.getAttribute("data-url");
    if (!url) return;

    var runningText = poller.getAttribute("data-running-text") || "Scanning…";
    var reloadDelay = parseInt(poller.getAttribute("data-reload-delay-ms") || "2000", 10);
    if (!Number.isFinite(reloadDelay) || reloadDelay < 0) reloadDelay = 2000;

    window.setInterval(function () {
      fetch(url)
        .then(function (res) { return res.json(); })
        .then(function (data) {
          if (!data || !data.status) return;

          if (data.status === "running") {
            ensureScanInfo(runningText);
          } else if (data.status === "done") {
            var scanInfo = document.getElementById("scan-info");
            if (scanInfo) {
              removeScanInfoAndReload(reloadDelay);
            }
          }
        })
        .catch(function (err) {
          console.error("Error fetching scan status:", err);
        });
    }, 2000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startScanStatusPolling);
  } else {
    startScanStatusPolling();
  }
})();
