import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync(new URL("./administrators.js", import.meta.url), "utf8");

test("administrator deletion opened for one tenant cannot be sent after switching tenants", async () => {
  let confirm;
  const calls = [];
  const context = vm.createContext({
    uiConfirm: () => new Promise(resolve => { confirm = resolve; }),
    apiFetch: async (...args) => { calls.push(args); return {ok: false,status:403}; },
    uiToast: () => {},
    renderAdminList: () => {},
    bl: x => x.en,
    encodeURIComponent,
  });
  vm.runInContext('let operateTenant = "Acme"; let idpSession = {subject:"operator"};', context);
  vm.runInContext(source, context);
  const pending = vm.runInContext('adminDelete({principal_id:"principal-a",email:"a@example.invalid"}, {})', context);
  assert.equal(typeof confirm, "function");
  vm.runInContext('operateTenant = "acme";', context);
  confirm(true);
  await pending;
  assert.equal(calls.length, 0);
});

test("administrator deletion still sends once when the tenant is unchanged", async () => {
  let confirm;
  const calls = [];
  const context = vm.createContext({
    uiConfirm: () => new Promise(resolve => { confirm = resolve; }),
    apiFetch: async (...args) => { calls.push(args); return {ok: false,status:403}; },
    uiToast: () => {},
    bl: x => x.en,
    encodeURIComponent,
  });
  vm.runInContext('let operateTenant = "Acme"; let idpSession = {subject:"operator"};', context);
  vm.runInContext(source, context);
  const pending = vm.runInContext('adminDelete({principal_id:"principal-a",email:"a@example.invalid"}, {})', context);
  confirm(true);
  await pending;
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], "DELETE");
});

test("suspend confirmation cannot be sent to a different tenant", async () => {
  let confirm;
  const calls = [];
  const context = vm.createContext({
    uiConfirm: () => new Promise(resolve => { confirm = resolve; }),
    apiFetch: async (...args) => { calls.push(args); return {ok: false,status:403}; },
    uiToast: () => {},
    bl: x => x.en,
    encodeURIComponent,
  });
  vm.runInContext('let operateTenant = "Acme"; let idpSession = {subject:"operator"};', context);
  vm.runInContext(source, context);
  const pending = vm.runInContext('adminStatusChange({principal_id:"principal-a",email:"a@example.invalid"}, "suspend", {})', context);
  vm.runInContext('operateTenant = "acme";', context);
  confirm(true);
  await pending;
  assert.equal(calls.length, 0);
});
