"use strict";

const byId = (id) => document.getElementById(id);
const array = (value) => Array.isArray(value) ? value : [];
const string = (value, fallback = "정보 없음") => typeof value === "string" && value ? value : fallback;
const number = (value) => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const priorities = {high: "높음", medium: "검토", low: "낮음", info: "정보", unknown: "미확인"};
const ruleNames = {
  "dangling-known-service": "연결 대상의 DNS 응답 확인 필요",
  "known-service-review": "서비스 연결 상태 확인 필요",
  "aws-infrastructure": "AWS 인프라 연결 단서",
};
const state = {report: null, selected: null, demo: true};

function node(tag, className, value) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (value !== undefined) element.textContent = value;
  return element;
}

function clear(element) {
  element.replaceChildren();
}

function priority(value) {
  const key = Object.hasOwn(priorities, value) ? value : "unknown";
  return node("span", `priority ${key}`, priorities[key]);
}

function timestamp(value) {
  if (typeof value !== "string" || !value) return "시간 정보 없음";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "시간 정보 없음" :
    new Intl.DateTimeFormat("ko-KR", {dateStyle: "medium", timeStyle: "short"}).format(date);
}

function validateReport(report) {
  if (!report || typeof report !== "object" || Array.isArray(report) || report.schema_version !== "1.0" ||
      typeof report.domain !== "string" || !report.domain || report.domain.length > 253 ||
      !Array.isArray(report.assets) || report.assets.length > 200) {
    throw new Error("PathLens report.json 형식이 아니거나 자산 수가 200개를 초과했습니다.");
  }
  for (const asset of report.assets) {
    if (!asset || typeof asset !== "object" || typeof asset.name !== "string" ||
        !asset.name || asset.name.length > 253 || !Object.hasOwn(priorities, asset.priority) ||
        !Array.isArray(asset.findings) || asset.findings.length > 100 ||
        !Array.isArray(asset.cname_chain) || asset.cname_chain.length > 9) {
      throw new Error("자산 정보의 형식이 올바르지 않습니다. PathLens 보고서인지 확인해 주세요.");
    }
  }
  return report;
}

function showNotice(message, error = false) {
  byId("notice-text").textContent = message;
  byId("report-notice").classList.toggle("error", error);
}

function loadReport(report, demo) {
  state.report = validateReport(report);
  state.demo = demo;
  state.selected = null;
  byId("asset-search").value = "";
  byId("priority-filter").value = "all";
  byId("report-domain").textContent = state.report.domain;
  const mode = state.report.collection_mode === "live" ? "공개 정보 조회" : "스냅샷";
  byId("report-meta").textContent = `${mode} · 관측 ${timestamp(state.report.observed_at)}`;
  byId("dataset-label").textContent = demo ? "가상 데모 데이터" : "로컬 보고서 · 출처 확인 필요";
  byId("dataset-label").classList.toggle("real", !demo);
  showNotice(demo ? "현재 화면은 가상 데이터입니다. 실제 자산이나 위협을 나타내지 않습니다." :
    "선택한 파일은 이 브라우저에서만 열립니다. 보고서의 출처와 관측 시각을 직접 확인해 주세요.");
  renderNotes();
  renderSummary();
  renderAssets();
  renderIntel();
}

function renderNotes() {
  const warnings = array(state.report.warnings);
  const limitations = array(state.report.limitations);
  const list = byId("report-notes-list");
  clear(list);
  for (const text of warnings.slice(0, 50)) list.append(node("li", "", `경고 · ${string(text)}`));
  for (const text of limitations.slice(0, 50)) list.append(node("li", "", `한계 · ${string(text)}`));
  const remaining = Math.max(0, warnings.length - 50) + Math.max(0, limitations.length - 50);
  if (remaining) list.append(node("li", "", `외 ${remaining}건은 원본 보고서에서 확인`));
  byId("notes-count").textContent = `· 경고 ${warnings.length}건 / 한계 ${limitations.length}건`;
}

function renderSummary() {
  const report = state.report;
  const assets = report.assets;
  byId("metric-assets").textContent = assets.length;
  byId("metric-high").textContent = assets.filter((asset) => asset.priority === "high").length;
  byId("metric-findings").textContent = assets.reduce((sum, asset) => sum + asset.findings.length, 0);
  const stix = report.stix_correlation || {};
  const feed = report.threat_feed || {};
  byId("metric-ti").textContent = number(feed.match_count) + number(stix.match_count);
}

function visibleAssets() {
  const query = byId("asset-search").value.trim().toLowerCase();
  const filter = byId("priority-filter").value;
  return state.report.assets.filter((asset) => asset.name.toLowerCase().includes(query) &&
    (filter === "all" || asset.priority === filter));
}

function renderAssets() {
  const assets = visibleAssets();
  const list = byId("asset-list");
  clear(list);
  byId("asset-count").textContent = `${assets.length} / ${state.report.assets.length} ASSETS`;
  byId("list-empty").hidden = assets.length !== 0;
  if (!assets.some((asset) => asset === state.selected)) state.selected = assets[0] || null;
  for (const asset of assets) {
    const button = node("button", "asset-row");
    button.type = "button";
    button.setAttribute("aria-pressed", String(asset === state.selected));
    const text = node("span", "asset-main");
    text.append(node("span", "asset-name", asset.name));
    const label = asset.findings.length ? `규칙 ${asset.findings.length}건` : "일치하는 규칙 없음";
    text.append(node("span", "asset-sub", label));
    button.append(text, priority(asset.priority));
    button.addEventListener("click", () => {
      state.selected = asset;
      for (const row of list.children) row.setAttribute("aria-pressed", String(row === button));
      renderDetail();
    });
    list.append(button);
  }
  renderDetail();
}

function sectionHeader(numberText, title) {
  const header = node("div", "block-head");
  header.append(node("span", "block-number", numberText), node("h3", "", title));
  return header;
}

function addEvidence(container, evidence) {
  const entries = array(evidence);
  if (!entries.length) return;
  const list = node("ul", "evidence-list");
  for (const item of entries.slice(0, 20)) {
    const line = node("li");
    line.append(node("span", "evidence-source", `${string(item?.source, "출처 미상")} · `));
    line.append(document.createTextNode(string(item?.description)));
    if (typeof item?.reference === "string") line.append(document.createTextNode(` (${item.reference})`));
    list.append(line);
  }
  if (entries.length > 20) list.append(node("li", "", `외 ${entries.length - 20}건은 원본 보고서에서 확인`));
  container.append(list);
}

function renderFinding(finding) {
  const container = node("article", "finding");
  const head = node("div", "finding-head");
  head.append(priority(finding?.priority), node("strong", "", ruleNames[finding?.rule_id] || string(finding?.title)));
  const body = node("div", "finding-body");
  body.append(node("p", "", string(finding?.explanation, "규칙 설명 없음")));
  if (finding?.action) {
    const action = node("p");
    action.append(node("strong", "", "확인할 내용  "), document.createTextNode(string(finding.action)));
    body.append(action);
  }
  addEvidence(body, finding?.evidence);
  container.append(head, body);
  return container;
}

function addAssetIntel(target, asset) {
  const groups = [
    ["지표 일치", asset.indicator_matches, (v) => `${string(v.indicator_type)} · ${string(v.value)} · ${string(v.status)}`],
    ["CVE / KEV", asset.vulnerability_matches, (v) => string(v.cve_id)],
    ["제품 / KEV 후보", asset.product_kev_candidates, (v) => `${string(v.cve_id)} · ${string(v.product)}`],
    ["OSV 권고", asset.osv_matches, (v) => string(v.advisory_id)],
    ["유출 주장", asset.exposure_claims, (v) => `${string(v.category)} · ${string(v.source_name)}`],
  ];
  const matched = groups.filter(([, items]) => array(items).length);
  if (!matched.length) return;
  const section = array(asset.threat_context).length ? "04" : "03";
  target.append(node("div", "detail-divider"), sectionHeader(section, "이 자산의 TI 단서"));
  const list = node("ul", "evidence-list");
  for (const [label, values, describe] of matched) {
    const items = array(values);
    for (const item of items.slice(0, 10)) list.append(node("li", "", `${label} · ${describe(item || {})}`));
    if (items.length > 10) list.append(node("li", "", `${label} 외 ${items.length - 10}건은 원본 보고서에서 확인`));
  }
  target.append(list, node("p", "detail-sub", "입력 정보와 일치하는 단서이며 실제 침해 또는 취약점의 증거는 아닙니다."));
}

function addThreatContexts(target, asset) {
  const contexts = array(asset.threat_context);
  if (!contexts.length) return;
  target.append(node("div", "detail-divider"), sectionHeader("03", "관련 보안 맥락"));
  for (const context of contexts.slice(0, 10)) {
    const item = node("article", "finding");
    const head = node("div", "finding-head");
    head.append(node("strong", "", string(context?.title)));
    const body = node("div", "finding-body");
    for (const [label, value] of [
      ["설명", context?.description], ["적용 범위", context?.applicability],
      ["확인할 내용", context?.action], ["한계", context?.limitations],
      ["출처", [context?.source_name, context?.source_url].filter(Boolean).join(" · ")],
    ]) {
      if (!value) continue;
      const line = node("p");
      line.append(node("strong", "", `${label}  `), document.createTextNode(string(value)));
      body.append(line);
    }
    item.append(head, body);
    target.append(item);
  }
  if (contexts.length > 10) target.append(node("p", "detail-sub", `외 ${contexts.length - 10}건은 원본 보고서에서 확인`));
}

function renderDetail() {
  const target = byId("asset-detail");
  clear(target);
  const asset = state.selected;
  if (!asset) { target.append(node("p", "empty-message", "목록에서 자산을 선택해 주세요.")); return; }
  const top = node("div", "detail-top");
  const title = node("div");
  title.append(node("div", "detail-kicker", "ASSET DETAIL / 관측된 자산"), node("h2", "detail-title", asset.name));
  title.append(node("div", "detail-sub", `발견 출처 · ${array(asset.discovered_by).join(", ") || "정보 없음"}`));
  top.append(title, priority(asset.priority));
  target.append(top, node("div", "detail-divider"), sectionHeader("01", "관측된 연결 경로"));
  const path = node("div", "path-box");
  const chain = array(asset.cname_chain);
  for (const [index, value] of chain.entries()) {
    const step = node("div", "path-item");
    const body = node("div", "path-value", string(value));
    body.append(node("span", "path-label", index === 0 ? "입력 자산" : `CNAME / ${String(index).padStart(2, "0")}`));
    step.append(node("span", "path-pin"), body);
    path.append(step);
  }
  if (!chain.length) path.append(node("span", "detail-sub", "연결 경로 정보 없음"));
  target.append(path, node("p", "address-line", `IP · ${array(asset.addresses).join(", ") || "관측 없음"}`));
  target.append(node("div", "detail-divider"), sectionHeader("02", "규칙 결과와 근거"));
  if (asset.findings.length) {
    for (const finding of asset.findings) target.append(renderFinding(finding || {}));
  } else {
    target.append(node("p", "no-findings", "일치하는 규칙이 없습니다. 안전하다는 의미는 아니며 추가 확인이 필요합니다."));
  }
  for (const warning of array(asset.warnings).slice(0, 20)) target.append(node("p", "detail-warnings", `! ${string(warning)}`));
  addThreatContexts(target, asset);
  addAssetIntel(target, asset);
}

function intelItem(title, value, note) {
  const item = node("div", "intel-item");
  item.append(node("span", "", title), node("strong", "", String(value)), node("small", "", note));
  return item;
}

function renderIntel() {
  const target = byId("intel-content");
  clear(target);
  const report = state.report;
  const feed = report.threat_feed || {};
  const stix = report.stix_correlation || {};
  const exposure = report.exposure_correlation || {};
  target.append(
    intelItem("TI 지표 일치", number(feed.match_count), feed.status === "loaded" ? "사용자 제공 피드와 비교" : "피드 미제공"),
    intelItem("STIX 패턴 일치", number(stix.match_count), stix.status === "loaded" ? `판단 보류 ${number(stix.indeterminate_count)}건` : "STIX 미제공"),
    intelItem("유출 주장", number(exposure.match_count), exposure.status === "loaded" ? "사용자 제공 · 미검증" : "주장 자료 미제공"),
  );
  if (stix.status === "loaded") {
    const list = node("div", "stix-list");
    list.append(node("strong", "", "STIX 패턴 결과 · 전체 보고서 기준"));
    const results = array(stix.results);
    for (const item of results.slice(0, 20)) {
      const label = {matched: "일치", not_matched: "일치 없음", indeterminate: "판단 보류"}[item?.status] || "미확인";
      const validity = item?.indicator_status ? ` · 유효 상태 ${item.indicator_status}` : "";
      list.append(node("p", "", `${label} · ${string(item?.indicator_id)}${validity}${item?.reason ? ` · ${item.reason}` : ""}`));
      for (const evidence of array(item?.evidence).slice(0, 20)) {
        list.append(node("p", "", `↳ DNS #${number(evidence?.dns_record_index)} · ${string(evidence?.name)} ${string(evidence?.record_type)} · ${array(evidence?.values).join(", ") || "값 없음"} · ${timestamp(evidence?.observed_at)}`));
      }
    }
    target.append(list);
  }
}

byId("demo-button").addEventListener("click", () => loadReport(window.PATHLENS_DEMO, true));
byId("asset-search").addEventListener("input", renderAssets);
byId("priority-filter").addEventListener("change", renderAssets);
byId("file-input").addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  try {
    if (file.size > 25 * 1024 * 1024) throw new Error("보고서 크기는 25 MiB를 넘을 수 없습니다.");
    loadReport(JSON.parse(await file.text()), false);
  } catch (error) {
    showNotice(error instanceof SyntaxError ? "JSON 파일을 읽을 수 없습니다." : string(error?.message), true);
  } finally {
    event.target.value = "";
  }
});
loadReport(window.PATHLENS_DEMO, true);
