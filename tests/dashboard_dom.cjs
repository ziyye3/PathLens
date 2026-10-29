"use strict";

// Lightweight DOM doubles exercise viewer state without starting a browser or network server.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

class Element {
  constructor(tag = "div") {
    this.tag = tag;
    this.children = [];
    this.events = {};
    this.attributes = {};
    this.value = "";
    this.textContent = "";
    this.hidden = false;
    this.classList = {toggle: (name, enabled) => { this.attributes[name] = enabled; }};
  }
  set className(value) { this.attributes.className = value; }
  set innerHTML(_) { throw new Error("Untrusted content must not use innerHTML"); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = items; }
  setAttribute(name, value) { this.attributes[name] = value; }
  addEventListener(name, handler) { this.events[name] = handler; }
}

function createDocument() {
  const elements = new Map();
  return {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, new Element());
      return elements.get(id);
    },
    createElement: (tag) => new Element(tag),
    createTextNode: (text) => ({textContent: text}),
  };
}

async function main() {
  const dashboard = path.join(__dirname, "../src/pathlens/dashboard");
  const document = createDocument();
  const context = vm.createContext({document, window: {}, console, Intl, Date});
  vm.runInContext(fs.readFileSync(path.join(dashboard, "demo.js"), "utf8"), context);
  vm.runInContext(fs.readFileSync(path.join(dashboard, "app.js"), "utf8"), context);
  const get = (id) => document.getElementById(id);
  assert.equal(get("metric-assets").textContent, 6);
  assert.equal(get("metric-high").textContent, 1);
  assert.match(get("dataset-label").textContent, /가상/);
  assert.equal(get("asset-list").children.length, 6);
  assert.match(get("notes-count").textContent, /경고/);
  const originalList = get("asset-list").children.slice();
  originalList[1].events.click();
  assert.equal(get("asset-list").children[1], originalList[1]);
  assert.equal(originalList[1].attributes["aria-pressed"], "true");
  assert.equal(originalList[0].attributes["aria-pressed"], "false");

  get("asset-search").value = "cdn.example.com";
  get("asset-search").events.input();
  assert.equal(get("asset-list").children.length, 1);
  get("priority-filter").value = "high";
  get("priority-filter").events.change();
  assert.equal(get("asset-list").children.length, 0);
  assert.equal(get("list-empty").hidden, false);

  const report = JSON.parse(JSON.stringify(context.window.PATHLENS_DEMO));
  report.assets[0].name = "<img src=x onerror=alert(1)>";
  const input = get("file-input");
  const valid = {size: 100, text: async () => JSON.stringify(report)};
  await input.events.change({target: {files: [valid], value: "report.json"}});
  assert.match(get("dataset-label").textContent, /로컬 보고서/);
  assert.equal(get("asset-list").children[0].children[0].children[0].textContent, report.assets[0].name);
  const bad = {size: 1, text: async () => "not json"};
  await input.events.change({target: {files: [bad], value: "bad.json"}});
  assert.match(get("notice-text").textContent, /JSON/);
  assert.equal(get("report-notice").attributes.error, true);
  const large = {size: 25 * 1024 * 1024 + 1, text: async () => {throw new Error("read");}};
  await input.events.change({target: {files: [large], value: "large.json"}});
  assert.match(get("notice-text").textContent, /25 MiB/);
  get("demo-button").events.click();
  assert.match(get("dataset-label").textContent, /가상/);
  console.log("dashboard state and offline file handling passed");
}

main().catch((error) => {console.error(error); process.exitCode = 1;});
