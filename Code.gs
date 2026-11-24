/**
 * e-Express Invoice Tracker — ESCM LLC
 * Google Apps Script backend (JSON API).
 *
 * Deployment: Web app, "Execute as: Me", "Who has access: Anyone".
 * Every request must carry a Google ID token from "Sign in with Google";
 * the token is verified server-side (audience, issuer, expiry, verified email)
 * and the email is then checked against the App_Users tab. Nothing is
 * returned to callers without a valid token from an approved, active user.
 */

// ---------------------------------------------------------------- CONFIG ---
// Defaults written to Script Properties by setup(). After setup, change values
// in Project Settings > Script Properties (no code edit needed).
var DEFAULT_CONFIG = {
  SPREADSHEET_ID: 'PUT_SPREADSHEET_ID_HERE',
  CLIENT_ID: 'PUT_OAUTH_CLIENT_ID_HERE.apps.googleusercontent.com',
  BOOTSTRAP_ADMIN: 'PUT_ADMIN_EMAIL_HERE',
  // Invoice Amount = Data Count x RATE, exactly as the sheet's "=B6*0.0415" formulas.
  RATE: '0.0415'
};
// Optional initial users created by setup() (only if not already present).
var INITIAL_USERS = [
  // { email: 'someone@gmail.com', role: 'Editor', batches: '*', records: '' }
];

var REGISTER_SHEET = 'Invoice Register';
var REGISTER_FIRST_ROW = 6;
var REGISTER_LAST_ROW = 205;          // range covered by the dashboard formulas
var REGISTER_PLACEHOLDER_LAST_ROW = 100; // rows that carried the "USD " placeholder
var REGISTER_PLACEHOLDER_CURRENCY = 'USD ';

var T_RECORDS = 'App_Records';
var T_USERS = 'App_Users';
var T_AUDIT = 'App_Audit';

var REC_COLS = ['id', 'seq', 'batchNumber', 'dataCount', 'invoiceNumber', 'invoiceDate',
  'currency', 'invoiceAmount', 'settlementStatus', 'version', 'createdAt', 'createdBy',
  'updatedAt', 'updatedBy', 'deleted'];
var USER_COLS = ['email', 'role', 'batches', 'records', 'active', 'updatedAt', 'updatedBy'];
var AUDIT_COLS = ['timestamp', 'actor', 'action', 'recordId', 'changes', 'requestId'];

var BUSINESS_FIELDS = ['batchNumber', 'dataCount', 'invoiceNumber', 'invoiceDate',
  'currency', 'invoiceAmount', 'settlementStatus'];
var STORED_FIELDS = ['batchNumber', 'dataCount', 'invoiceNumber', 'invoiceDate', 'currency', 'settlementStatus'];
var STATUSES = ['Pending', 'Partially Settled', 'Settled'];
var ROLES = ['Admin', 'Editor', 'Viewer'];
var MAX_PAGE_SIZE = 100;

// ------------------------------------------------------------- ENTRY ---
function doGet() {
  return json_({ ok: true, service: 'e-Express Invoice Tracker API' });
}

function doPost(e) {
  var req;
  try {
    req = JSON.parse((e && e.postData && e.postData.contents) || '{}');
  } catch (err) {
    return json_(fail_('BAD_REQUEST', 'Request body is not valid JSON.'));
  }
  return json_(handle_(req));
}

/** Core dispatcher (also used directly by the test harness). */
function handle_(req) {
  try {
    if (!req || typeof req !== 'object') throw apiError_('BAD_REQUEST', 'Missing request.');
    var action = String(req.action || '');
    var email = verifyIdToken_(req.idToken);           // throws UNAUTHENTICATED
    var user = getUser_(email);                         // throws FORBIDDEN
    var p = req.payload || {};
    switch (action) {
      case 'me': return ok_({ email: user.email, role: user.role, batches: user.batches, records: user.records, rate: Number(config_().RATE) });
      case 'list': return ok_(listRecords_(user, p));
      case 'dashboard': return ok_(dashboard_(user, p));
      case 'export': return ok_(exportCsv_(user, p));
      case 'batches': return ok_(visibleBatches_(user));
      case 'create': return withIdempotency_(req, function () { return createRecord_(user, p, req.requestId); });
      case 'update': return withIdempotency_(req, function () { return updateRecord_(user, p, req.requestId); });
      case 'delete': return withIdempotency_(req, function () { return deleteRecord_(user, p, req.requestId); });
      case 'users.list': requireAdmin_(user); return ok_(listUsers_());
      case 'users.save': requireAdmin_(user); return withIdempotency_(req, function () { return saveUser_(user, p, req.requestId); });
      case 'users.remove': requireAdmin_(user); return withIdempotency_(req, function () { return removeUser_(user, p, req.requestId); });
      case 'audit.list': requireAdmin_(user); return ok_(listAudit_(p));
      default: throw apiError_('BAD_REQUEST', 'Unknown action.');
    }
  } catch (err) {
    if (err && err.apiCode) return fail_(err.apiCode, err.message, err.extra);
    var msg = String((err && err.message) || err);
    if (/too many times|quota|Rate Limit|Bandwidth/i.test(msg)) {
      return fail_('QUOTA', 'Google service limit reached. Please wait a minute and try again.');
    }
    if (/lock/i.test(msg)) return fail_('BUSY', 'The tracker is busy. Please try again.');
    console.error(err && err.stack || msg);
    return fail_('SERVER_ERROR', 'Unexpected server error. Please try again.');
  }
}

// ------------------------------------------------------------- AUTH ---
function verifyIdToken_(token) {
  if (!token || typeof token !== 'string' || token.length > 4096) {
    throw apiError_('UNAUTHENTICATED', 'Sign-in required.');
  }
  var cache = CacheService.getScriptCache();
  var key = 'tok_' + sha256_(token);
  var hit = cache.get(key);
  if (hit) return hit;

  var res;
  try {
    res = UrlFetchApp.fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(token),
      { muteHttpExceptions: true });
  } catch (err) {
    throw apiError_('AUTH_UNAVAILABLE', 'Could not verify sign-in with Google. Please try again.');
  }
  if (res.getResponseCode() !== 200) throw apiError_('UNAUTHENTICATED', 'Sign-in expired or invalid. Please sign in again.');
  var info = JSON.parse(res.getContentText());
  var now = Math.floor(Date.now() / 1000);
  var cfg = config_();
  if (info.aud !== cfg.CLIENT_ID) throw apiError_('UNAUTHENTICATED', 'Sign-in was not issued for this app.');
  if (info.iss !== 'accounts.google.com' && info.iss !== 'https://accounts.google.com') {
    throw apiError_('UNAUTHENTICATED', 'Invalid sign-in issuer.');
  }
  if (!(Number(info.exp) > now)) throw apiError_('UNAUTHENTICATED', 'Sign-in expired. Please sign in again.');
  if (String(info.email_verified) !== 'true' || !info.email) {
    throw apiError_('UNAUTHENTICATED', 'Google account email is not verified.');
  }
  var email = String(info.email).toLowerCase();
  var ttl = Math.min(21600, Number(info.exp) - now - 30);
  if (ttl > 0) cache.put(key, email, ttl);
  return email;
}

function getUser_(email) {
  var users = readTable_(T_USERS, USER_COLS);
  for (var i = 0; i < users.length; i++) {
    var u = users[i];
    if (String(u.email).toLowerCase() === email && truthy_(u.active)) {
      return {
        email: email,
        role: ROLES.indexOf(u.role) >= 0 ? u.role : 'Viewer',
        batches: parseList_(u.batches),
        records: parseList_(u.records)
      };
    }
  }
  throw apiError_('FORBIDDEN', 'Your Google account (' + email + ') is not approved for this tracker. Ask an Admin for access.');
}

function requireAdmin_(user) {
  if (user.role !== 'Admin') throw apiError_('FORBIDDEN', 'Admin access required.');
}

function canSeeRecord_(user, rec) {
  if (user.role === 'Admin') return true;
  if (user.batches.indexOf('*') >= 0) return true;
  if (user.batches.indexOf(rec.batchNumber) >= 0) return true;
  if (user.records.indexOf(rec.id) >= 0) return true;
  return false;
}

/** Editors may write to records they can see; new/moved records must land in an assigned batch. */
function canWriteBatch_(user, batch) {
  if (user.role === 'Admin') return true;
  if (user.role !== 'Editor') return false;
  return user.batches.indexOf('*') >= 0 || user.batches.indexOf(batch) >= 0;
}

// ------------------------------------------------------------ RECORDS ---
function visibleRecords_(user) {
  return readTable_(T_RECORDS, REC_COLS)
    .filter(function (r) { return r.id && !truthy_(r.deleted); })
    .map(normalizeRecord_)
    .filter(function (r) { return canSeeRecord_(user, r); });
}

function normalizeRecord_(r) {
  return {
    id: String(r.id),
    seq: Number(r.seq) || 0,
    batchNumber: str_(r.batchNumber),
    dataCount: numOrNull_(r.dataCount),
    invoiceNumber: str_(r.invoiceNumber),
    invoiceDate: dateStr_(r.invoiceDate),
    currency: str_(r.currency).trim().toUpperCase(),
    invoiceAmount: amountFor_(numOrNull_(r.dataCount)),
    rawAmount: rawAmountFor_(numOrNull_(r.dataCount)),
    settlementStatus: str_(r.settlementStatus),
    version: Number(r.version) || 1,
    createdAt: isoOrStr_(r.createdAt),
    createdBy: str_(r.createdBy),
    updatedAt: isoOrStr_(r.updatedAt),
    updatedBy: str_(r.updatedBy)
  };
}

function applyFilters_(recs, f) {
  f = f || {};
  var q = str_(f.q).trim().toLowerCase();
  var cur = str_(f.currency).trim().toUpperCase();
  var st = str_(f.status);
  var batch = str_(f.batch);
  var from = str_(f.dateFrom), to = str_(f.dateTo);
  return recs.filter(function (r) {
    if (q && r.batchNumber.toLowerCase().indexOf(q) < 0 && r.invoiceNumber.toLowerCase().indexOf(q) < 0) return false;
    if (cur && r.currency !== cur) return false;
    if (st) {
      if (st === '__none__') { if (r.settlementStatus) return false; }
      else if (r.settlementStatus !== st) return false;
    }
    if (batch && r.batchNumber !== batch) return false;
    if (from && (!r.invoiceDate || r.invoiceDate < from)) return false;
    if (to && (!r.invoiceDate || r.invoiceDate > to)) return false;
    return true;
  });
}

var SORTABLE = { batchNumber: 1, dataCount: 1, invoiceNumber: 1, invoiceDate: 1, currency: 1, invoiceAmount: 1, settlementStatus: 1, seq: 1, updatedAt: 1 };

function sortRecords_(recs, sortBy, dir) {
  var key = SORTABLE[sortBy] ? sortBy : 'seq';
  var mul = dir === 'desc' ? -1 : 1;
  return recs.slice().sort(function (a, b) {
    var x = a[key], y = b[key];
    var xe = (x === null || x === '' || x === undefined), ye = (y === null || y === '' || y === undefined);
    if (xe && ye) return a.seq - b.seq;
    if (xe) return 1;           // blanks always last
    if (ye) return -1;
    if (typeof x === 'number' && typeof y === 'number') return (x - y) * mul || (a.seq - b.seq);
    var c = String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: 'base' });
    return c * mul || (a.seq - b.seq);
  });
}

function listRecords_(user, p) {
  var recs = sortRecords_(applyFilters_(visibleRecords_(user), p.filters), p.sortBy, p.sortDir);
  var size = Math.max(1, Math.min(MAX_PAGE_SIZE, Number(p.pageSize) || 25));
  var pages = Math.max(1, Math.ceil(recs.length / size));
  var page = Math.max(1, Math.min(pages, Number(p.page) || 1));
  return {
    total: recs.length, page: page, pageSize: size, pages: pages,
    items: recs.slice((page - 1) * size, page * size),
    canCreate: user.role === 'Admin' || (user.role === 'Editor' && user.batches.length > 0),
    role: user.role
  };
}

function visibleBatches_(user) {
  var seen = {};
  visibleRecords_(user).forEach(function (r) { if (r.batchNumber) seen[r.batchNumber] = 1; });
  return { batches: Object.keys(seen).sort(function (a, b) { return a.localeCompare(b, undefined, { numeric: true }); }) };
}

function validateRecord_(input) {
  var errors = {};
  var out = {};
  var batch = str_(input.batchNumber).trim();
  if (!batch) errors.batchNumber = 'Batch Number is required.';
  else if (batch.length > 80) errors.batchNumber = 'Batch Number is too long (max 80).';
  out.batchNumber = batch;

  var dc = input.dataCount;
  if (dc === '' || dc === null || dc === undefined) out.dataCount = null;
  else {
    var n = Number(String(dc).replace(/,/g, ''));
    if (!isFinite(n) || n < 0 || Math.floor(n) !== n) errors.dataCount = 'Data Count must be a whole number 0 or more.';
    else if (n > 1e12) errors.dataCount = 'Data Count is too large.';
    out.dataCount = n;
  }

  var inv = str_(input.invoiceNumber).trim();
  if (inv.length > 60) errors.invoiceNumber = 'Invoice Number is too long (max 60).';
  out.invoiceNumber = inv;

  var d = str_(input.invoiceDate).trim();
  if (d) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(d) || !validDate_(d)) errors.invoiceDate = 'Invoice Date must be a valid date.';
  }
  out.invoiceDate = d;

  // Blank currency defaults to USD, matching the "USD" pre-filled down the sheet.
  var cur = str_(input.currency).trim().toUpperCase() || 'USD';
  if (!/^[A-Z]{3}$/.test(cur)) errors.currency = 'Currency must be a 3-letter code such as USD.';
  out.currency = cur;

  // Invoice Amount is never taken from the browser: it is calculated (Data Count x rate), as in the sheet.
  out.invoiceAmount = amountFor_(out.dataCount === undefined ? null : out.dataCount);

  var st = str_(input.settlementStatus).trim();
  if (st && STATUSES.indexOf(st) < 0) errors.settlementStatus = 'Choose Pending, Partially Settled or Settled.';
  out.settlementStatus = st;

  if (Object.keys(errors).length) throw apiError_('VALIDATION', 'Please correct the highlighted fields.', { fields: errors });
  return out;
}

function createRecord_(user, p, requestId) {
  if (user.role === 'Viewer') throw apiError_('FORBIDDEN', 'Viewers cannot create records.');
  var data = validateRecord_(p.record || {});
  if (!canWriteBatch_(user, data.batchNumber)) throw apiError_('FORBIDDEN', 'You are not assigned to batch "' + data.batchNumber + '".');
  return withLock_(function () {
    var all = readTable_(T_RECORDS, REC_COLS);
    checkDuplicateInvoice_(all, data, null);
    var maxSeq = 0;
    all.forEach(function (r) { maxSeq = Math.max(maxSeq, Number(r.seq) || 0); });
    var now = new Date().toISOString();
    var rec = {};
    STORED_FIELDS.forEach(function (k) { rec[k] = data[k]; });
    rec.invoiceAmount = '';
    rec.id = 'inv_' + Utilities.getUuid().replace(/-/g, '').slice(0, 16);
    rec.seq = maxSeq + 1;
    rec.version = 1;
    rec.createdAt = now; rec.createdBy = user.email;
    rec.updatedAt = now; rec.updatedBy = user.email;
    rec.deleted = false;
    appendRow_(T_RECORDS, REC_COLS, rec);
    var changes = {};
    BUSINESS_FIELDS.forEach(function (k) { if (data[k] !== null && data[k] !== '') changes[k] = [null, data[k]]; });
    audit_(user.email, 'create', rec.id, changes, requestId);
    syncRegister_();
    return { record: normalizeRecord_(rec) };
  });
}

function updateRecord_(user, p, requestId) {
  if (user.role === 'Viewer') throw apiError_('FORBIDDEN', 'Viewers cannot edit records.');
  var id = str_(p.id);
  var expected = Number(p.version);
  var data = validateRecord_(p.record || {});
  return withLock_(function () {
    var table = readTableWithRows_(T_RECORDS, REC_COLS);
    var hit = null;
    table.forEach(function (t) { if (String(t.obj.id) === id && !truthy_(t.obj.deleted)) hit = t; });
    if (!hit) throw apiError_('NOT_FOUND', 'Record not found.');
    var cur = normalizeRecord_(hit.obj);
    if (!canSeeRecord_(user, cur)) throw apiError_('NOT_FOUND', 'Record not found.');
    if (!canWriteBatch_(user, cur.batchNumber) && !(user.role === 'Editor' && user.records.indexOf(cur.id) >= 0)) {
      throw apiError_('FORBIDDEN', 'You do not have edit access to this record.');
    }
    if (data.batchNumber !== cur.batchNumber && !canWriteBatch_(user, data.batchNumber)) {
      throw apiError_('FORBIDDEN', 'You are not assigned to batch "' + data.batchNumber + '".');
    }
    if (cur.version !== expected) {
      throw apiError_('CONFLICT', 'This invoice was changed by ' + (cur.updatedBy || 'someone else') +
        ' since you opened it. Reload to see the latest version.', { current: cur });
    }
    checkDuplicateInvoice_(table.map(function (t) { return t.obj; }), data, id);
    var changes = {};
    BUSINESS_FIELDS.forEach(function (k) {
      var a = cur[k] === '' ? null : cur[k], b = data[k] === '' ? null : data[k];
      if (a !== b) changes[k] = [a, b];
    });
    if (!Object.keys(changes).length) return { record: cur, unchanged: true };
    var next = {};
    REC_COLS.forEach(function (c) { next[c] = hit.obj[c]; });
    STORED_FIELDS.forEach(function (k) { next[k] = data[k]; });
    next.invoiceAmount = '';
    next.version = cur.version + 1;
    next.updatedAt = new Date().toISOString();
    next.updatedBy = user.email;
    writeRow_(T_RECORDS, REC_COLS, hit.row, next);
    audit_(user.email, 'update', id, changes, requestId);
    syncRegister_();
    return { record: normalizeRecord_(next) };
  });
}

function deleteRecord_(user, p, requestId) {
  if (user.role !== 'Admin') throw apiError_('FORBIDDEN', 'Only Admins can delete records.');
  var id = str_(p.id);
  var expected = Number(p.version);
  return withLock_(function () {
    var table = readTableWithRows_(T_RECORDS, REC_COLS);
    var hit = null;
    table.forEach(function (t) { if (String(t.obj.id) === id && !truthy_(t.obj.deleted)) hit = t; });
    if (!hit) throw apiError_('NOT_FOUND', 'Record not found.');
    var cur = normalizeRecord_(hit.obj);
    if (cur.version !== expected) throw apiError_('CONFLICT', 'This invoice changed since you opened it. Reload and try again.');
    var next = {};
    REC_COLS.forEach(function (c) { next[c] = hit.obj[c]; });
    next.deleted = true;
    next.version = cur.version + 1;
    next.updatedAt = new Date().toISOString();
    next.updatedBy = user.email;
    writeRow_(T_RECORDS, REC_COLS, hit.row, next);
    var snapshot = {};
    BUSINESS_FIELDS.forEach(function (k) { snapshot[k] = [cur[k], null]; });
    audit_(user.email, 'delete', id, snapshot, requestId);
    syncRegister_();
    return { deleted: id };
  });
}

function checkDuplicateInvoice_(all, data, selfId) {
  if (!data.invoiceNumber) return;
  var key = data.invoiceNumber.toLowerCase();
  for (var i = 0; i < all.length; i++) {
    var r = all[i];
    if (truthy_(r.deleted) || String(r.id) === selfId) continue;
    if (str_(r.invoiceNumber).trim().toLowerCase() === key) {
      throw apiError_('VALIDATION', 'Invoice Number ' + data.invoiceNumber + ' already exists.', { fields: { invoiceNumber: 'This invoice number is already used.' } });
    }
  }
}

// ---------------------------------------------------------- DASHBOARD ---
function dashboard_(user, p) {
  var recs = applyFilters_(visibleRecords_(user), p.filters);
  var byCur = {}, months = {}, batches = {}, statusCounts = {};
  STATUSES.forEach(function (s) { statusCounts[s] = 0; });
  var totalDataCount = 0, issued = 0, numberedNoAmount = 0, awaitingInvoice = 0, noStatus = 0;
  var allAmount = {}; // sheet-style SUM of every row's amount, per currency

  function cur_(c) {
    if (!byCur[c]) {
      byCur[c] = { currency: c, invoiced: 0, settled: 0, partiallySettled: 0, pending: 0, noStatus: 0,
        outstanding: 0, notInvoiced: 0, issuedCount: 0, settledCount: 0, partiallySettledCount: 0, pendingCount: 0 };
    }
    return byCur[c];
  }

  recs.forEach(function (r) {
    if (r.dataCount !== null) totalDataCount += r.dataCount;
    var b = batches[r.batchNumber] || (batches[r.batchNumber] = {
      batchNumber: r.batchNumber, dataCount: 0, records: 0, issued: 0, settledCount: 0,
      partiallySettledCount: 0, pendingCount: 0, amounts: {}
    });
    b.records++;
    if (r.dataCount !== null) b.dataCount += r.dataCount;
    if (r.settlementStatus && statusCounts.hasOwnProperty(r.settlementStatus)) statusCounts[r.settlementStatus]++;
    else noStatus++;
    if (r.settlementStatus === 'Settled') b.settledCount++;
    if (r.settlementStatus === 'Partially Settled') b.partiallySettledCount++;
    if (r.settlementStatus === 'Pending') b.pendingCount++;

    var hasAmt = r.invoiceAmount !== null && !!r.currency;
    if (!r.invoiceNumber) {
      awaitingInvoice++;
      // Billable amount from Data Count, but no invoice issued yet: shown separately, never as invoiced.
      if (hasAmt && r.invoiceAmount > 0) { var cn = cur_(r.currency); cn.notInvoiced = (cn.notInvoiced + r.rawAmount); }
      return;
    }
    if (!hasAmt) { numberedNoAmount++; return; }
    // An invoice only counts as issued (and only adds to money totals) when it has an amount.
    issued++;
    b.issued++;
    var c = cur_(r.currency);
    var amt = r.rawAmount;  // unrounded, like the sheet's SUM/SUMIF of the formula column
    c.invoiced = (c.invoiced + amt);
    c.issuedCount++;
    var ba = b.amounts[r.currency] || (b.amounts[r.currency] = { invoiced: 0, settled: 0, outstanding: 0 });
    ba.invoiced = (ba.invoiced + amt);
    if (r.settlementStatus === 'Settled') { c.settled = (c.settled + amt); c.settledCount++; ba.settled = (ba.settled + amt); }
    else if (r.settlementStatus === 'Partially Settled') { c.partiallySettled = (c.partiallySettled + amt); c.partiallySettledCount++; ba.outstanding = (ba.outstanding + amt); }
    else if (r.settlementStatus === 'Pending') { c.pending = (c.pending + amt); c.pendingCount++; ba.outstanding = (ba.outstanding + amt); }
    else { c.noStatus = (c.noStatus + amt); }
    c.outstanding = (c.pending + c.partiallySettled);
    if (r.invoiceDate) {
      var m = r.invoiceDate.slice(0, 7);
      months[m] = months[m] || {};
      months[m][r.currency] = ((months[m][r.currency] || 0) + amt);
    }
  });

  roundDeep_(byCur); roundDeep_(months); roundDeep_(batches);
  var invoiceNumberCount = recs.filter(function (r) { return !!r.invoiceNumber; }).length;
  return {
    recordCount: recs.length,
    totalInvoices: invoiceNumberCount,      // as in the sheet: COUNTA of Invoice Number
    issuedInvoices: issued,                 // invoice number/amount present (amount required)
    numberedNoAmount: numberedNoAmount,
    awaitingInvoice: awaitingInvoice,
    totalDataCount: totalDataCount,
    statusCounts: statusCounts,             // as in the sheet: COUNTIF per status
    noStatusCount: noStatus,
    currencies: Object.keys(byCur).sort().map(function (k) { return byCur[k]; }),
    monthly: Object.keys(months).sort().map(function (m) { return { month: m, amounts: months[m] }; }),
    batches: Object.keys(batches).sort(function (a, b) { return a.localeCompare(b, undefined, { numeric: true }); })
      .map(function (k) { return batches[k]; })
  };
}

// ------------------------------------------------------------- EXPORT ---
function exportCsv_(user, p) {
  var recs = sortRecords_(applyFilters_(visibleRecords_(user), p.filters), p.sortBy, p.sortDir);
  var head = ['Batch Number', 'Data Count', 'Invoice Number', 'Invoice Date', 'Currency', 'Invoice Amount', 'Settlement Status'];
  var lines = [head.map(csvCell_).join(',')];
  recs.forEach(function (r) {
    lines.push([r.batchNumber, r.dataCount === null ? '' : r.dataCount, r.invoiceNumber, r.invoiceDate,
      r.currency, r.invoiceAmount === null ? '' : r.invoiceAmount.toFixed(2), r.settlementStatus].map(csvCell_).join(','));
  });
  return { filename: 'e-express-invoices-' + todayStr_() + '.csv', csv: '﻿' + lines.join('\r\n'), count: recs.length };
}

function csvCell_(v) {
  var s = v === null || v === undefined ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s) && !/^-?\d+(\.\d+)?$/.test(s)) s = "'" + s;   // neutralise formulas in Excel/Sheets
  if (/[",\r\n]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
  return s;
}

// -------------------------------------------------------------- USERS ---
function listUsers_() {
  var users = readTable_(T_USERS, USER_COLS).filter(function (u) { return u.email; }).map(function (u) {
    return { email: String(u.email).toLowerCase(), role: u.role, batches: parseList_(u.batches),
      records: parseList_(u.records), active: truthy_(u.active), updatedAt: isoOrStr_(u.updatedAt), updatedBy: str_(u.updatedBy) };
  });
  var allBatches = {};
  readTable_(T_RECORDS, REC_COLS).forEach(function (r) { if (!truthy_(r.deleted) && r.batchNumber) allBatches[str_(r.batchNumber)] = 1; });
  return { users: users, batches: Object.keys(allBatches).sort(function (a, b) { return a.localeCompare(b, undefined, { numeric: true }); }) };
}

function saveUser_(admin, p, requestId) {
  var u = p.user || {};
  var email = str_(u.email).trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) throw apiError_('VALIDATION', 'Enter a valid email address.', { fields: { email: 'Invalid email.' } });
  if (ROLES.indexOf(u.role) < 0) throw apiError_('VALIDATION', 'Choose a valid role.', { fields: { role: 'Invalid role.' } });
  if (email === admin.email) throw apiError_('FORBIDDEN', 'You cannot change your own role or access. Ask another Admin.');
  var batches = (Array.isArray(u.batches) ? u.batches : parseList_(u.batches)).map(function (b) { return str_(b).trim(); }).filter(String);
  var records = (Array.isArray(u.records) ? u.records : parseList_(u.records)).map(function (b) { return str_(b).trim(); }).filter(String);
  batches.concat(records).forEach(function (b) {
    if (b.length > 80 || /[,]/.test(b)) throw apiError_('VALIDATION', 'Invalid batch or record entry.');
  });
  var active = u.active === undefined ? true : !!u.active;
  return withLock_(function () {
    var table = readTableWithRows_(T_USERS, USER_COLS);
    var hit = null;
    table.forEach(function (t) { if (String(t.obj.email).toLowerCase() === email) hit = t; });
    var before = hit ? { role: hit.obj.role, batches: str_(hit.obj.batches), records: str_(hit.obj.records), active: truthy_(hit.obj.active) } : null;
    var row = { email: email, role: u.role, batches: batches.join(','), records: records.join(','), active: active,
      updatedAt: new Date().toISOString(), updatedBy: admin.email };
    if (hit) writeRow_(T_USERS, USER_COLS, hit.row, row);
    else appendRow_(T_USERS, USER_COLS, row);
    audit_(admin.email, hit ? 'user.update' : 'user.add', email,
      { before: before, after: { role: row.role, batches: row.batches, records: row.records, active: active } }, requestId);
    return listUsers_();
  });
}

function removeUser_(admin, p, requestId) {
  var email = str_(p.email).trim().toLowerCase();
  if (email === admin.email) throw apiError_('FORBIDDEN', 'You cannot remove your own access.');
  return withLock_(function () {
    var table = readTableWithRows_(T_USERS, USER_COLS);
    var hit = null;
    table.forEach(function (t) { if (String(t.obj.email).toLowerCase() === email) hit = t; });
    if (!hit) throw apiError_('NOT_FOUND', 'User not found.');
    sheet_(T_USERS).deleteRow(hit.row);
    audit_(admin.email, 'user.remove', email, { before: { role: hit.obj.role, batches: str_(hit.obj.batches), records: str_(hit.obj.records) } }, requestId);
    return listUsers_();
  });
}

function listAudit_(p) {
  var rows = readTable_(T_AUDIT, AUDIT_COLS).filter(function (a) { return a.timestamp; });
  var q = str_(p.recordId);
  if (q) rows = rows.filter(function (a) { return String(a.recordId) === q; });
  rows.reverse();
  var size = Math.max(1, Math.min(MAX_PAGE_SIZE, Number(p.pageSize) || 50));
  var pages = Math.max(1, Math.ceil(rows.length / size));
  var page = Math.max(1, Math.min(pages, Number(p.page) || 1));
  return {
    total: rows.length, page: page, pages: pages,
    items: rows.slice((page - 1) * size, page * size).map(function (a) {
      var ch; try { ch = JSON.parse(a.changes); } catch (e) { ch = a.changes; }
      return { timestamp: isoOrStr_(a.timestamp), actor: str_(a.actor), action: str_(a.action), recordId: str_(a.recordId), changes: ch };
    })
  };
}

function audit_(actor, action, recordId, changes, requestId) {
  appendRow_(T_AUDIT, AUDIT_COLS, {
    timestamp: new Date().toISOString(), actor: actor, action: action, recordId: recordId,
    changes: JSON.stringify(changes), requestId: str_(requestId)
  });
}

// --------------------------------------------------- REGISTER MIRROR ---
/**
 * Writes the seven business fields of every live record into the original
 * "Invoice Register" tab (rows 6–205) so the existing Management Dashboard
 * formulas and chart keep working unchanged. Formulas, formatting, the logo,
 * validation and conditional formatting are never touched; only values in A:G.
 */
function syncRegister_() {
  var sh = ss_().getSheetByName(REGISTER_SHEET);
  if (!sh) return;
  var recs = readTable_(T_RECORDS, REC_COLS).filter(function (r) { return r.id && !truthy_(r.deleted); })
    .map(normalizeRecord_).sort(function (a, b) { return a.seq - b.seq; });
  var capacity = REGISTER_LAST_ROW - REGISTER_FIRST_ROW + 1;
  // Columns A:E and G are written; column F (Invoice Amount) keeps the sheet's own
  // "=B{row}*0.0415" formulas. Rows past the formula range get the same formula when used.
  var left = [], status = [];
  var fRange = sh.getRange(REGISTER_FIRST_ROW, 6, capacity, 1);
  var fFormulas = fRange.getFormulas();
  var rate = config_().RATE;
  for (var i = 0; i < capacity; i++) {
    var row = REGISTER_FIRST_ROW + i;
    var r = recs[i];
    if (r) {
      left.push([
        safeText_(r.batchNumber),
        r.dataCount === null ? '' : r.dataCount,
        safeText_(r.invoiceNumber),
        r.invoiceDate ? parseDate_(r.invoiceDate) : '',
        r.currency ? safeText_(r.currency + ' ') : ''    // keep the sheet's "USD " style
      ]);
      status.push([safeText_(r.settlementStatus)]);
      if (!fFormulas[i][0]) sh.getRange(row, 6).setFormula('=B' + row + '*' + rate);
    } else {
      left.push(['', '', '', '', row <= REGISTER_PLACEHOLDER_LAST_ROW ? REGISTER_PLACEHOLDER_CURRENCY : '']);
      status.push(['']);
    }
  }
  sh.getRange(REGISTER_FIRST_ROW, 1, capacity, 5).setValues(left);
  sh.getRange(REGISTER_FIRST_ROW, 7, capacity, 1).setValues(status);
  if (recs.length > capacity) console.warn('More than ' + capacity + ' records; register mirror truncated.');
}

// -------------------------------------------------------------- SETUP ---
/**
 * Run once from the Apps Script editor (Run > setup). Idempotent.
 * Creates App_* tabs, imports existing Invoice Register rows (with stable IDs),
 * and adds the bootstrap Admin + initial users. Does not modify existing tabs.
 */
function setup() {
  var props = PropertiesService.getScriptProperties();
  Object.keys(DEFAULT_CONFIG).forEach(function (k) {
    if (!props.getProperty(k)) props.setProperty(k, DEFAULT_CONFIG[k]);
  });
  var ss = ss_();
  ensureSheet_(T_RECORDS, REC_COLS);
  ensureSheet_(T_USERS, USER_COLS);
  ensureSheet_(T_AUDIT, AUDIT_COLS);

  var existing = readTable_(T_RECORDS, REC_COLS).filter(function (r) { return r.id; });
  var imported = 0;
  if (!existing.length) {
    var reg = ss.getSheetByName(REGISTER_SHEET);
    if (!reg) throw new Error('Invoice Register tab not found.');
    var vals = reg.getRange(REGISTER_FIRST_ROW, 1, REGISTER_LAST_ROW - REGISTER_FIRST_ROW + 1, 7).getValues();
    var now = new Date().toISOString();
    vals.forEach(function (v) {
      // A row is a record only if it has something other than the currency placeholder.
      // (Column F is a formula of column B, so it is not used to decide.)
      var hasData = [0, 1, 2, 3, 6].some(function (i) { return v[i] !== '' && v[i] !== null; });
      if (!hasData) return;
      imported++;
      var rec = {
        id: 'inv_' + Utilities.getUuid().replace(/-/g, '').slice(0, 16), seq: imported,
        batchNumber: str_(v[0]).trim(), dataCount: v[1] === '' ? '' : Number(v[1]),
        invoiceNumber: str_(v[2]).trim(), invoiceDate: v[3] ? dateStr_(v[3]) : '',
        currency: str_(v[4]).trim().toUpperCase(), invoiceAmount: '',
        settlementStatus: str_(v[6]).trim(), version: 1, createdAt: now, createdBy: 'import',
        updatedAt: now, updatedBy: 'import', deleted: false
      };
      appendRow_(T_RECORDS, REC_COLS, rec);
      audit_('import', 'import', rec.id, { source: 'Invoice Register row ' + (REGISTER_FIRST_ROW + imported - 1) }, '');
    });
  }

  var users = readTable_(T_USERS, USER_COLS);
  var have = {};
  users.forEach(function (u) { have[String(u.email).toLowerCase()] = 1; });
  var admin = String(props.getProperty('BOOTSTRAP_ADMIN') || '').toLowerCase();
  var now2 = new Date().toISOString();
  if (admin && !have[admin]) {
    appendRow_(T_USERS, USER_COLS, { email: admin, role: 'Admin', batches: '*', records: '', active: true, updatedAt: now2, updatedBy: 'setup' });
    have[admin] = 1;
  }
  INITIAL_USERS.forEach(function (u) {
    var e = u.email.toLowerCase();
    if (have[e]) return;
    appendRow_(T_USERS, USER_COLS, { email: e, role: u.role, batches: u.batches, records: u.records || '', active: true, updatedAt: now2, updatedBy: 'setup' });
    have[e] = 1;
  });
  var msg = 'Setup complete. Imported ' + imported + ' record(s). Users: ' + Object.keys(have).join(', ');
  console.log(msg);
  return msg;
}

function ensureSheet_(name, cols) {
  var ss = ss_();
  var sh = ss.getSheetByName(name);
  if (!sh) {
    sh = ss.insertSheet(name);
    sh.getRange(1, 1, sh.getMaxRows(), cols.length).setNumberFormat('@'); // store everything as text
    sh.getRange(1, 1, 1, cols.length).setValues([cols]).setFontWeight('bold');
    sh.setFrozenRows(1);
    try { sh.hideSheet(); } catch (e) { }
    try {
      var prot = sh.protect().setDescription('Managed by e-Express Invoice Tracker app');
      prot.setWarningOnly(true);
    } catch (e) { }
  }
  return sh;
}

// ------------------------------------------------------------ HELPERS ---
function config_() {
  var props = PropertiesService.getScriptProperties();
  var out = {};
  Object.keys(DEFAULT_CONFIG).forEach(function (k) { out[k] = props.getProperty(k) || DEFAULT_CONFIG[k]; });
  return out;
}

var __ss = null;
function ss_() {
  if (!__ss) __ss = SpreadsheetApp.openById(config_().SPREADSHEET_ID);
  return __ss;
}

function sheet_(name) {
  var sh = ss_().getSheetByName(name);
  if (!sh) throw apiError_('SERVER_ERROR', 'Tracker is not set up yet (missing ' + name + ').');
  return sh;
}

function readTableWithRows_(name, cols) {
  var sh = sheet_(name);
  var last = sh.getLastRow();
  if (last < 2) return [];
  var vals = sh.getRange(2, 1, last - 1, cols.length).getValues();
  var out = [];
  for (var i = 0; i < vals.length; i++) {
    var o = {};
    for (var j = 0; j < cols.length; j++) o[cols[j]] = unescape_(vals[i][j]);
    out.push({ row: i + 2, obj: o });
  }
  return out;
}

function readTable_(name, cols) {
  return readTableWithRows_(name, cols).map(function (t) { return t.obj; });
}

function toRow_(cols, obj) {
  return cols.map(function (c) {
    var v = obj[c];
    if (v === null || v === undefined) return '';
    if (typeof v === 'boolean') return v ? 'TRUE' : 'FALSE';
    if (typeof v === 'number') return String(v);
    return safeText_(String(v));
  });
}

function appendRow_(name, cols, obj) {
  var sh = sheet_(name);
  var row = sh.getLastRow() + 1;
  sh.getRange(row, 1, 1, cols.length).setNumberFormat('@').setValues([toRow_(cols, obj)]);
}

function writeRow_(name, cols, row, obj) {
  sheet_(name).getRange(row, 1, 1, cols.length).setValues([toRow_(cols, obj)]);
}

/** Prevent spreadsheet formula injection: text starting with = + - @ is stored as literal text. */
function safeText_(s) {
  s = String(s);
  if (/^[=+\-@\t\r]/.test(s)) return "'" + s;
  return s;
}

/** Reverse safeText_ if the sheet kept the protective apostrophe. */
function unescape_(v) {
  return (typeof v === 'string' && /^'[=+\-@\t\r]/.test(v)) ? v.slice(1) : v;
}

function withLock_(fn) {
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(15000)) throw apiError_('BUSY', 'Another change is being saved. Please try again in a moment.');
  try { return fn(); } finally { SpreadsheetApp.flush(); lock.releaseLock(); }
}

/** Duplicate-submission guard: the same requestId returns the first result instead of writing twice. */
function withIdempotency_(req, fn) {
  var rid = str_(req.requestId);
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(rid)) throw apiError_('BAD_REQUEST', 'Missing request id.');
  var cache = CacheService.getScriptCache();
  var key = 'req_' + rid;
  var prev = cache.get(key);
  if (prev) { var r = JSON.parse(prev); r.duplicate = true; return r; }
  var result = ok_(fn());
  try { cache.put(key, JSON.stringify(result), 21600); } catch (e) { cache.put(key, JSON.stringify({ ok: true, data: null }), 21600); }
  return result;
}

function apiError_(code, message, extra) {
  var e = new Error(message);
  e.apiCode = code; e.extra = extra;
  return e;
}
function ok_(data) { return { ok: true, data: data }; }
function fail_(code, message, extra) { return { ok: false, error: { code: code, message: message, details: extra || null } }; }
function json_(obj) { return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON); }

function str_(v) { return v === null || v === undefined ? '' : String(v); }
function truthy_(v) { return v === true || String(v).toUpperCase() === 'TRUE'; }
function numOrNull_(v) { if (v === '' || v === null || v === undefined) return null; var n = Number(v); return isFinite(n) ? n : null; }
// Round half-up on the decimal value (avoids 0.884999... float artefacts), like the sheet's display.
function round2_(n) { return Math.round(Number((n * 100).toFixed(6))) / 100; }
function rawAmountFor_(count) {
  if (count === null || count === undefined) return null;
  var rate = Number(config_().RATE);
  return isFinite(rate) ? count * rate : null;
}
function roundDeep_(o) {
  Object.keys(o).forEach(function (k) {
    if (typeof o[k] === 'number' && !/Count$|^records$|^issued$|^dataCount$/.test(k)) o[k] = round2_(o[k]);
    else if (o[k] && typeof o[k] === 'object') roundDeep_(o[k]);
  });
}
function amountFor_(count) {
  if (count === null || count === undefined) return null;
  var rate = Number(config_().RATE);
  return isFinite(rate) ? round2_(count * rate) : null;
}
function parseList_(v) { return str_(v).split(',').map(function (s) { return s.trim(); }).filter(String); }
function isoOrStr_(v) { return v instanceof Date ? v.toISOString() : str_(v); }
function pad_(n) { return (n < 10 ? '0' : '') + n; }
function dateStr_(v) {
  if (!v) return '';
  if (v instanceof Date) {
    return Utilities.formatDate(v, ss_().getSpreadsheetTimeZone(), 'yyyy-MM-dd');
  }
  var s = String(v).trim();
  return /^\d{4}-\d{2}-\d{2}/.test(s) ? s.slice(0, 10) : s;
}
function validDate_(s) {
  var p = s.split('-').map(Number);
  var d = new Date(Date.UTC(p[0], p[1] - 1, p[2]));
  return d.getUTCFullYear() === p[0] && d.getUTCMonth() === p[1] - 1 && d.getUTCDate() === p[2] && p[0] >= 1990 && p[0] <= 2100;
}
// Script time zone is set to the spreadsheet's (Asia/Dhaka) in appsscript.json, so this is local midnight.
function parseDate_(s) { var p = s.split('-').map(Number); return new Date(p[0], p[1] - 1, p[2]); }
function todayStr_() { var d = new Date(); return d.getFullYear() + '-' + pad_(d.getMonth() + 1) + '-' + pad_(d.getDate()); }
function sha256_(s) {
  var bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, s, Utilities.Charset.UTF_8);
  return bytes.map(function (b) { return ('0' + ((b + 256) % 256).toString(16)).slice(-2); }).join('');
}
