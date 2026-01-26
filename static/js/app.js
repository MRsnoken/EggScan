(function () {
  console.log("[EggScan] app.js loaded");

  function normalize(s) {
    return (s || "").toString().trim().toLowerCase();
  }

  function t(key) {
    var dict = window.EGGS_I18N || {};
    return dict[key] || key;
  }

  function debounce(fn, ms) {
    var t = null;
    return function () {
      var args = arguments;
      clearTimeout(t);
      t = setTimeout(function () {
        fn.apply(null, args);
      }, ms);
    };
  }

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

  function removeScanInfo() {
    var scanInfo = document.getElementById("scan-info");
    if (scanInfo) scanInfo.remove();
  }

  function getFlashContainer() {
    var existing = document.querySelector(".js-flash-container");
    if (existing) return existing;

    var cardBody = document.querySelector(".card-body");
    if (!cardBody) return null;

    var wrap = document.createElement("div");
    wrap.className = "mb-3 js-flash-container";
    cardBody.insertBefore(wrap, cardBody.firstChild);
    return wrap;
  }

  function scheduleFlashDismiss(alertEl) {
    if (!alertEl) return;
    setTimeout(function () {
      alertEl.classList.add("flash-hide");
      setTimeout(function () {
        if (alertEl && alertEl.parentNode) {
          alertEl.parentNode.removeChild(alertEl);
        }
      }, 350);
    }, 15000);
  }

  function showFlash(kind, key) {
    var container = getFlashContainer();
    if (!container) return;
    var alertEl = document.createElement("div");
    alertEl.className = "alert alert-" + kind + " mb-1 js-flash-alert";
    alertEl.setAttribute("role", "alert");
    alertEl.textContent = t(key);
    container.insertBefore(alertEl, container.firstChild);
    scheduleFlashDismiss(alertEl);
  }

  function hardReload(delayMs) {
    window.setTimeout(function () {
      window.location.reload();
    }, delayMs);
  }

  function applyLiveFilter() {
    var searchInput = document.getElementById("liveSearch");
    var filterSelect = document.getElementById("liveFilter");
    var table = document.getElementById("devicesTable");
    if (!searchInput || !filterSelect || !table) return;

    var q = normalize(searchInput.value);
    var mode = normalize(filterSelect.value);

    var tbody = table.querySelector("tbody");
    if (!tbody) return;

    var rows = tbody.querySelectorAll("tr");
    var visible = 0;

    rows.forEach(function (row) {
      if (row && row.id === "noResultsRow") return;

      var rowStatus = normalize(row.getAttribute("data-status"));
      var hay = normalize(row.getAttribute("data-search"));

      var okStatus = true;
      if (mode === "online") okStatus = (rowStatus === "online");
      else if (mode === "offline") okStatus = (rowStatus === "offline");

      var okSearch = !q || (hay && hay.indexOf(q) !== -1);

      var show = okStatus && okSearch;
      row.style.display = show ? "" : "none";
      if (show) visible += 1;
    });

    var noResultsRow = document.getElementById("noResultsRow");
    if (noResultsRow) {
      noResultsRow.style.display = visible === 0 ? "" : "none";
    }
  }

  var updatePending = false;

  function getUpdateButton() {
    return document.getElementById("scanUpdateBtn");
  }

  function showUpdateButton() {
    var btn = getUpdateButton();
    if (!btn) return;

    var label = btn.getAttribute("data-label") || "Update";
    var title = btn.getAttribute("data-title") || "New scan results available";

    btn.textContent = label;
    btn.title = title;
    btn.style.display = "";
  }

  function hideUpdateButton() {
    var btn = getUpdateButton();
    if (!btn) return;
    btn.style.display = "none";
  }

function isAnyModalOpen() {
  return !!document.querySelector(".modal.show");
}

  function getSearchInput() {
    return document.getElementById("liveSearch");
  }

  function hasSearchText() {
    var s = getSearchInput();
    if (!s) return false;
    return s.value && s.value.trim().length > 0;
  }

  function shouldAutoReloadWhenScanDone() {
    if (isAnyModalOpen()) return false;
    if (hasSearchText()) return false;
    return true;
  }

  function onScanDone(reloadDelay) {
    removeScanInfo();

    if (shouldAutoReloadWhenScanDone()) {
      hideUpdateButton();
      updatePending = false;
      hardReload(reloadDelay);
      return;
    }

    updatePending = true;
    showUpdateButton();
  }

  function startScanStatusPolling() {
    var poller = document.getElementById("scan-status-poller");
    if (!poller) return;

    var url = poller.getAttribute("data-url");
    if (!url) return;

    var runningText = poller.getAttribute("data-running-text") || "Scanning…";
    var reloadDelay = parseInt(poller.getAttribute("data-reload-delay-ms") || "2000", 10);
    if (!Number.isFinite(reloadDelay) || reloadDelay < 0) reloadDelay = 2000;

    var lastStatus = null;

    var scanStatusErrorShown = false;

    window.setInterval(function () {
      fetch(url)
        .then(function (res) { return res.json(); })
        .then(function (data) {
          if (!data || !data.status) return;

          var status = data.status;

          if (status === "running") {
            ensureScanInfo(runningText);
          }

          if (lastStatus === "running" && status === "done") {
            onScanDone(reloadDelay);
          }

          lastStatus = status;
        })
        .catch(function (err) {
          console.error("Error fetching scan status:", err);
          if (!scanStatusErrorShown) {
            showFlash("warning", "FLASH_AJAX_SCAN_STATUS_FAIL");
            scanStatusErrorShown = true;
          }
        });
    }, 2000);
  }

  function startLiveSearchFilter() {
    var searchInput = document.getElementById("liveSearch");
    var filterSelect = document.getElementById("liveFilter");
    var table = document.getElementById("devicesTable");
    if (!searchInput || !filterSelect || !table) return;

    var debounced = debounce(function () {
      applyLiveFilter();

      if (updatePending && !isAnyModalOpen() && !hasSearchText()) {
        hideUpdateButton();
        updatePending = false;
        hardReload(200);
      }
    }, 80);

    searchInput.addEventListener("input", debounced);
    filterSelect.addEventListener("change", function () {
      applyLiveFilter();
    });

    applyLiveFilter();
  }

  function hookUpdateButtonClick() {
    var btn = getUpdateButton();
    if (!btn) return;

    btn.addEventListener("click", function () {
      hideUpdateButton();
      updatePending = false;
      hardReload(50);
    });
  }

function hookModalCloseForPendingReload() {
  function tryFinishPendingReload() {
    if (!updatePending) return;
    if (hasSearchText()) return;

    
    if (isAnyModalOpen()) return;

    hideUpdateButton();
    updatePending = false;
    hardReload(150);
  }

  function scheduleTries() {
   
    window.setTimeout(tryFinishPendingReload, 0);
    window.setTimeout(tryFinishPendingReload, 50);
    window.setTimeout(tryFinishPendingReload, 150);
    window.setTimeout(tryFinishPendingReload, 300);
    window.setTimeout(tryFinishPendingReload, 600);
  }


  document.addEventListener("hide.bs.modal", function () {
    scheduleTries();
  }, true);

  document.addEventListener("hidden.bs.modal", function () {
    scheduleTries();
  }, true);

  
  document.addEventListener("click", function (e) {
    var dismissBtn =
      (e.target && e.target.closest && e.target.closest('[data-dismiss="modal"], [data-bs-dismiss="modal"]')) || null;

    if (dismissBtn) {
      scheduleTries();
    }
  }, true);


  document.addEventListener("mousedown", function (e) {
    var modalEl = e.target && e.target.closest ? e.target.closest(".modal") : null;
    if (!modalEl) return;


    if (e.target === modalEl) {
      scheduleTries();
    }
  }, true);

 
  document.addEventListener("keydown", function (e) {
    var key = e.key || e.keyCode;
    if (key === "Escape" || key === "Esc" || key === 27) {
      scheduleTries();
    }
  }, true);
}

  function getMarkKnownBaseUrl() {
    var el = document.getElementById("mark-known-endpoints");
    if (!el) return null;
    var url = (el.getAttribute("data-url") || "").trim();
    if (!url) return null;
    return url;
  }

  function buildMarkKnownUrl(deviceId) {
    var base = getMarkKnownBaseUrl();
    if (!base) return null;

    var idStr = String(deviceId);

    if (base.indexOf("/0") !== -1) {
      return base.replace("/0", "/" + idStr);
    }

    if (base.match(/\/\d+$/)) {
      return base.replace(/\/\d+$/, "/" + idStr);
    }

    if (base.endsWith("/")) return base + idStr;
    return base + "/" + idStr;
  }

  function findRowByDeviceId(deviceId) {
    var table = document.getElementById("devicesTable");
    if (!table) return null;
    return table.querySelector('tr[data-device-id="' + String(deviceId) + '"]');
  }

  function parseFirstInt(text) {
    if (!text) return null;
    var m = String(text).match(/-?\d+/);
    if (!m) return null;
    var n = parseInt(m[0], 10);
    return Number.isFinite(n) ? n : null;
  }

  function decrementIntInElement(el) {
    if (!el) return false;
    var current = parseFirstInt(el.textContent);
    if (current === null) return false;

    var next = current - 1;
    if (next < 0) next = 0;

    el.textContent = el.textContent.replace(/-?\d+/, String(next));
    return true;
  }

  function decrementNewCountersEverywhere() {
    var did = false;

       var ids = [
      "newDevicesCount",
      "statusbarNewCount",
      "statsNewDevicesCount",
      "newCount"
    ];

    ids.forEach(function (id) {
      var el = document.getElementById(id);
      if (el && el.children.length === 0) {
        did = decrementIntInElement(el) || did;
      }
    });

    if (did) return true;

   
    function isLeaf(el) {
      return el && el.nodeType === 1 && el.children && el.children.length === 0;
    }

    function isNumberOnly(el) {
      if (!isLeaf(el)) return false;
      var txt = (el.textContent || "").trim();
      return /^[0-9]+$/.test(txt);
    }

    function findNearestNumberForLabel(labelEl) {
      if (!labelEl) return null;

      var p = labelEl.parentElement;
      if (p) {
        var all = p.querySelectorAll("*");
        for (var i = 0; i < all.length; i++) {
          var c = all[i];
          if (c === labelEl) continue;
          if (isNumberOnly(c)) return c;
        }
      }

      var sib = labelEl.nextElementSibling;
      if (isNumberOnly(sib)) return sib;

      if (p && p.nextElementSibling && isNumberOnly(p.nextElementSibling)) {
        return p.nextElementSibling;
      }

      return null;
    }

    var candidates = document.querySelectorAll("span, strong, small, b, div, td, th, p, h1, h2, h3, h4, h5, h6");
    var labels = [];

    candidates.forEach(function (el) {
      if (!isLeaf(el)) return;
      var txt = normalize(el.textContent);
      if (
        txt === "nya enheter" || txt === "nya enheter:" ||
        txt === "new devices" || txt === "new devices:"
      ) {
        labels.push(el);
      }
    });

    var updatedAny = false;

    for (var j = 0; j < labels.length; j++) {
      var labelEl = labels[j];
      var numEl = findNearestNumberForLabel(labelEl);
      if (numEl) {
        updatedAny = decrementIntInElement(numEl) || updatedAny;
      }
    }

    return updatedAny;
  }

  function removeBlinkClasses(row) {
    if (!row || !row.classList) return;

    row.classList.remove("blink");
    row.classList.remove("new-blink");
    row.classList.remove("blink-new");
    row.classList.remove("device-new");
    row.classList.remove("is-new");

    Array.from(row.classList).forEach(function (c) {
      if (String(c).toLowerCase().indexOf("blink") !== -1) {
        row.classList.remove(c);
      }
    });
  }

  function removeNewUiFromRow(row) {
    if (!row) return;

    row.setAttribute("data-is-new", "0");
    removeBlinkClasses(row);

    var badge = row.querySelector(".device-new-badge");
    if (badge) badge.style.display = "none";

    var btn = row.querySelector(".js-mark-known");
    if (btn) btn.remove();
  }

  function hookMarkKnownAjax() {
    function getCsrfToken() {
      var meta = document.querySelector('meta[name="csrf-token"]');
      return meta ? meta.getAttribute("content") : "";
    }

    function stopAll(e) {
      if (!e) return;
      e.preventDefault();
      e.stopPropagation();
      if (typeof e.stopImmediatePropagation === "function") e.stopImmediatePropagation();
    }

    document.addEventListener("submit", function (e) {
      var submitter = e.submitter || null;
      if (submitter && submitter.classList && submitter.classList.contains("js-mark-known")) {
        stopAll(e);
      }
    }, true);

    document.addEventListener("click", function (e) {
      var btn = e.target && e.target.closest ? e.target.closest(".js-mark-known") : null;
      if (!btn) return;

      stopAll(e);

      var deviceId = btn.getAttribute("data-device-id");
      if (!deviceId) return;

      var url = buildMarkKnownUrl(deviceId);
      if (!url) {
        console.error("No mark-known URL configured (missing #mark-known-endpoints data-url).");
        return;
      }

      btn.disabled = true;

      var csrfToken = getCsrfToken();

      fetch(url, {
        method: "POST",
        headers: {
          "X-Requested-With": "XMLHttpRequest",
          "X-CSRF-Token": csrfToken
        }
      })
        .then(function (res) {
          if (!res.ok) throw new Error("HTTP " + res.status);
          return res.json();
        })
        .then(function (data) {
          if (!data || data.ok !== true) {
            btn.disabled = false;
            showFlash("danger", "FLASH_AJAX_MARK_KNOWN_FAIL");
            return;
          }

          var row = findRowByDeviceId(deviceId);
          removeNewUiFromRow(row);

          if (data.changed === true) {
            decrementNewCountersEverywhere();
          }
        })
        .catch(function (err) {
          console.error("Mark known failed:", err);
          btn.disabled = false;
          showFlash("danger", "FLASH_AJAX_MARK_KNOWN_FAIL");
        });
    }, true);
  }

  function initTagInputs() {
    var datalist = document.getElementById("deviceTagList");
    if (!datalist) return;

    var baseTags = Array.from(datalist.querySelectorAll("option"))
      .map(function (opt) { return opt.value; })
      .filter(Boolean);

    var tagInputs = Array.from(document.querySelectorAll(".tag-input"));
    if (!tagInputs.length) return;

    function normalizeTag(raw) {
      var tag = String(raw || "").trim();
      if (!tag) return "";
      return tag.replace(/\s+/g, " ").toLowerCase();
    }

    function parseTags(raw) {
      var tags = [];
      var seen = {};
      String(raw || "").split(",").forEach(function (part) {
        var tag = normalizeTag(part);
        if (!tag || seen[tag]) return;
        seen[tag] = true;
        tags.push(tag);
      });
      return tags;
    }

    function serializeTags(tags) {
      return tags.join(", ");
    }

    function buildOptions() {
      if (!baseTags.length) return;
      datalist.innerHTML = "";
      baseTags.forEach(function (tag) {
        var opt = document.createElement("option");
        opt.value = tag;
        datalist.appendChild(opt);
      });
    }

    buildOptions();

    tagInputs.forEach(function (wrap) {
      var chipList = wrap.querySelector(".tag-chip-list");
      var input = wrap.querySelector(".tag-input-field");
      var hidden = wrap.querySelector("input[type='hidden'][name='tags']");
      var initial = (wrap.getAttribute("data-tags-initial") || (hidden ? hidden.value : ""));
      var tags = parseTags(initial);

      function syncHidden() {
        if (hidden) hidden.value = serializeTags(tags);
      }

      function render() {
        if (!chipList) return;
        chipList.innerHTML = "";
        tags.forEach(function (tag) {
          var chip = document.createElement("span");
          chip.className = "tag-chip";
          chip.textContent = tag;

          var btn = document.createElement("button");
          btn.type = "button";
          btn.className = "tag-chip-remove";
          btn.setAttribute("aria-label", "Remove tag");
          btn.textContent = "×";
          btn.addEventListener("click", function () {
            tags = tags.filter(function (t) { return t !== tag; });
            render();
          });

          chip.appendChild(btn);
          chipList.appendChild(chip);
        });
        syncHidden();
      }

      function addTag(raw) {
        var tag = normalizeTag(raw);
        if (!tag) return;
        if (tags.indexOf(tag) !== -1) return;
        tags.push(tag);
        if (baseTags.indexOf(tag) === -1) {
          baseTags.push(tag);
          buildOptions();
        }
        render();
      }

      function consumeInputTokens() {
        if (!input) return;
        var value = input.value || "";
        if (!value) return;
        var parts = value.split(",");
        if (parts.length === 1) return;
        parts.slice(0, -1).forEach(addTag);
        input.value = parts[parts.length - 1].trim();
      }

      if (input) {
        input.addEventListener("keydown", function (e) {
          if (e.key === "Enter" || e.key === ",") {
            e.preventDefault();
            addTag(input.value);
            input.value = "";
          }
        });

        input.addEventListener("blur", function () {
          addTag(input.value);
          input.value = "";
        });

        input.addEventListener("input", consumeInputTokens);
      }

      render();
    });
  }

  function initFlashAutoDismiss() {
    var alerts = document.querySelectorAll(".js-flash-alert");
    if (!alerts.length) return;
    alerts.forEach(function (alertEl) {
      scheduleFlashDismiss(alertEl);
    });
  }

  function init() {
    startScanStatusPolling();
    startLiveSearchFilter();
    hookUpdateButtonClick();
    hookModalCloseForPendingReload();
    hookMarkKnownAjax();
    initTagInputs();
    initFlashAutoDismiss();
    initSubnetDragAndDrop();
  }
function initSubnetDragAndDrop() {
  var tbody = document.getElementById("subnetSortable");
  if (!tbody) return;

  var draggedRow = null;

  tbody.addEventListener("dragstart", function (e) {
    draggedRow = e.target.closest("tr");
    if (draggedRow) draggedRow.classList.add("dragging");
  });

  tbody.addEventListener("drop", function (e) {
  e.preventDefault();
  saveSubnetOrder();
});

  tbody.addEventListener("dragover", function (e) {
    e.preventDefault();
    var targetRow = e.target.closest("tr");
    if (!draggedRow || !targetRow || draggedRow === targetRow) return;

    var rect = targetRow.getBoundingClientRect();
    var next = (e.clientY - rect.top) > (rect.height / 2);
    tbody.insertBefore(draggedRow, next ? targetRow.nextSibling : targetRow);
  });

function saveSubnetOrder() {
  var ids = [];
  tbody.querySelectorAll("tr").forEach(function (tr) {
    var id = tr.getAttribute("data-subnet-id");
    if (id) ids.push(id);
  });

  var meta = document.querySelector('meta[name="csrf-token"]');
  var csrfToken = meta ? meta.getAttribute("content") : "";

  fetch("/update_subnet_order", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "XMLHttpRequest",
      "X-CSRF-Token": csrfToken
    },
    body: JSON.stringify({ order: ids })
  })
    .then(function (res) {
      if (res.redirected) {
        console.error("Redirected while saving subnet order:", res.url);
        throw new Error("Redirected");
      }
      if (!res.ok) {
        throw new Error("HTTP " + res.status);
      }
      return res.json();
    })
    .then(function (data) {
      if (!data || data.ok !== true) {
        throw new Error("Server returned ok=false");
      }
      console.log("Subnet order saved:", ids);
    })
    .catch(function (err) {
      console.error("Failed to save subnet order:", err);
      showFlash("danger", "FLASH_AJAX_SUBNET_ORDER_FAIL");
    });
}
}
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
  
})();
