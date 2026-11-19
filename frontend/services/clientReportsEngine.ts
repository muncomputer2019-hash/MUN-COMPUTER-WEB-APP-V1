import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocs,
  serverTimestamp,
  setDoc,
  updateDoc,
} from 'firebase/firestore';
import { auth, db } from './firebase';
import { sha256Hex } from './clientCryptoAuditService';
import type {
  AnalyticsDashboardPayload,
  BuilderDataSourceKey,
  BuilderDataSourceSchema,
  CalculatedColumnRule,
  CustomFilterRule,
  CustomReportExecutionRequest,
  CustomReportTemplate,
  ReportArchiveItem,
  ReportAuditLogItem,
  ReportCatalogItem,
  ReportColumnDef,
  ReportDataset,
  ReportFilterInput,
  ReportingDashboardData,
  ScheduledReportItem,
  ScheduleRunItem,
} from './reportApi';

export interface ReportsActorContext {
  userId: string;
  role: string;
  fullName: string;
}

function requireDb() {
  if (!db || !auth?.currentUser) {
    throw new Error('Firebase authenticated session required.');
  }
  return { db, uid: auth.currentUser.uid };
}

function toIsoDate(val: unknown): string {
  if (!val) return '';
  if (typeof val === 'string') return val.slice(0, 10);
  if (typeof val === 'object' && val !== null && 'toDate' in val && typeof (val as { toDate: () => Date }).toDate === 'function') {
    return (val as { toDate: () => Date }).toDate().toISOString().slice(0, 10);
  }
  return '';
}

function toIsoTimestamp(val: unknown): string {
  if (!val) return new Date().toISOString();
  if (typeof val === 'string') return val;
  if (typeof val === 'object' && val !== null && 'toDate' in val && typeof (val as { toDate: () => Date }).toDate === 'function') {
    return (val as { toDate: () => Date }).toDate().toISOString();
  }
  return new Date().toISOString();
}

function currentFinancialYear(): string {
  const now = new Date();
  const y = now.getFullYear();
  const m = now.getMonth() + 1;
  const start = m >= 4 ? y : y - 1;
  return `${start}-${String((start + 1) % 100).padStart(2, '0')}`;
}

export const REPORT_CATALOG_LIST: ReportCatalogItem[] = [
  {
    reportKey: 'CUSTOMER_LIST',
    title: 'Customer Master Directory & Balances',
    titleBn: 'গ্রাহক তালিকা ও বকেয়া',
    category: 'CUSTOMER',
    description: 'Complete registered customer profiles with village, contact, and billing summary.',
    financialRestricted: false,
    enabled: true,
  },
  {
    reportKey: 'CUSTOMER_DUES',
    title: 'Customer Outstanding Dues & Recovery',
    titleBn: 'গ্রাহক বকেয়া রিপোর্ট',
    category: 'CUSTOMER',
    description: 'Customers with pending application or invoice balances requiring follow-up.',
    financialRestricted: true,
    enabled: true,
  },
  {
    reportKey: 'APPLICATIONS_MASTER',
    title: 'Applications Processing & Turnaround',
    titleBn: 'আবেদন ও সেবা রিপোর্ট',
    category: 'APPLICATION_SERVICE',
    description: 'Status-wise applications breakdown with fees billed, collected, and due.',
    financialRestricted: false,
    enabled: true,
  },
  {
    reportKey: 'SERVICE_WISE_REVENUE',
    title: 'Service-Wise Volume & Revenue',
    titleBn: 'পরিষেবা ভিত্তিক আয়',
    category: 'APPLICATION_SERVICE',
    description: 'Grouped volume and net revenue across digital portal & CSC services.',
    financialRestricted: true,
    enabled: true,
  },
  {
    reportKey: 'STAFF_PERFORMANCE',
    title: 'Operator & Staff Performance Scorecard',
    titleBn: 'কর্মী কর্মক্ষমতা',
    category: 'APPLICATION_SERVICE',
    description: 'Completion rates, pending tasks, and collections handled per staff user.',
    financialRestricted: false,
    enabled: true,
  },
  {
    reportKey: 'INCOME_LEDGER',
    title: 'Confirmed Collections & Payment Ledger',
    titleBn: 'আয়ের খাতা',
    category: 'FINANCIAL',
    description: 'Itemized receipts across Cash, UPI, Card, and Bank Transfer modes.',
    financialRestricted: true,
    enabled: true,
  },
  {
    reportKey: 'EXPENSE_LEDGER',
    title: 'Operational Expense Vouchers',
    titleBn: 'ব্যয়ের খাতা',
    category: 'FINANCIAL',
    description: 'Recorded office, utility, stationery, and operational expenditure vouchers.',
    financialRestricted: true,
    enabled: true,
  },
  {
    reportKey: 'PROFIT_LOSS_STATEMENT',
    title: 'Income vs Expense Profit & Loss Summary',
    titleBn: 'লাভ-ক্ষতি বিবরণী',
    category: 'FINANCIAL',
    description: 'Net profit, total collections, expenses, and refunds across the active period.',
    financialRestricted: true,
    enabled: true,
  },
  {
    reportKey: 'PRODUCTS_STOCK_REPORT',
    title: 'Products & Inventory Valuation',
    titleBn: 'পণ্য ও মজুদ রিপোর্ট',
    category: 'BUSINESS_INVENTORY',
    description: 'Current stock quantities, reorder alerts, and inventory valuation.',
    financialRestricted: false,
    enabled: true,
  },
  {
    reportKey: 'EMPLOYEE_PAYROLL_REPORT',
    title: 'Employee Compensation & Payroll Register',
    titleBn: 'কর্মচারী বেতন রিপোর্ট',
    category: 'BUSINESS_INVENTORY',
    description: 'Active payroll master, gross earnings, PF/TDS deductions, and net payable.',
    financialRestricted: true,
    enabled: true,
  },
  {
    reportKey: 'CSC_ORDERS_REPORT',
    title: 'CSC Service Orders Register',
    titleBn: 'সিএসসি অর্ডার রিপোর্ট',
    category: 'CSC_OPERATIONS',
    description: 'Digital Seva & citizen portal multi-service orders with rate snapshots.',
    financialRestricted: false,
    enabled: true,
  },
  {
    reportKey: 'PVC_PRINTING_REPORT',
    title: 'PVC Card Printing & Wholesale Slabs',
    titleBn: 'পিভিসি কার্ড প্রিন্টিং',
    category: 'CSC_OPERATIONS',
    description: 'Individual and wholesale PVC smart card print batches and collections.',
    financialRestricted: false,
    enabled: true,
  },
  {
    reportKey: 'GRIEVANCE_RTI_REPORT',
    title: 'Public Grievance & RTI Dossiers',
    titleBn: 'অভিযোগ ও আরটিআই',
    category: 'CSC_OPERATIONS',
    description: 'Citizen grievance redressal tracking and SLA resolution status.',
    financialRestricted: false,
    enabled: true,
  },
];

export const BUILDER_SCHEMAS: BuilderDataSourceSchema[] = [
  {
    key: 'CUSTOMERS',
    label: 'Customers CRM',
    fields: [
      { key: 'customerId', label: 'Customer ID', type: 'text' },
      { key: 'fullName', label: 'Full Name', type: 'text' },
      { key: 'mobile', label: 'Mobile', type: 'text' },
      { key: 'village', label: 'Village / Town', type: 'text' },
      { key: 'district', label: 'District', type: 'text' },
      { key: 'segment', label: 'Segment', type: 'text' },
      { key: 'status', label: 'Status', type: 'status' },
      { key: 'createdDate', label: 'Registered Date', type: 'date' },
    ],
  },
  {
    key: 'APPLICATIONS',
    label: 'Applications & Services',
    fields: [
      { key: 'applicationNo', label: 'Application No', type: 'text' },
      { key: 'customerName', label: 'Customer Name', type: 'text' },
      { key: 'serviceName', label: 'Service Name', type: 'text' },
      { key: 'status', label: 'Status', type: 'status' },
      { key: 'assignedStaffId', label: 'Assigned Staff', type: 'text' },
      { key: 'totalFee', label: 'Total Fee (INR)', type: 'currency' },
      { key: 'paidAmount', label: 'Paid Amount (INR)', type: 'currency' },
      { key: 'dueAmount', label: 'Due Amount (INR)', type: 'currency' },
      { key: 'applicationDate', label: 'Application Date', type: 'date' },
    ],
  },
  {
    key: 'PAYMENTS',
    label: 'Payments & Receipts',
    fields: [
      { key: 'transactionId', label: 'Transaction ID', type: 'text' },
      { key: 'receiptNo', label: 'Receipt No', type: 'text' },
      { key: 'applicationNo', label: 'Application No', type: 'text' },
      { key: 'paymentMethod', label: 'Payment Method', type: 'text' },
      { key: 'amount', label: 'Amount (INR)', type: 'currency' },
      { key: 'verificationStatus', label: 'Status', type: 'status' },
      { key: 'paymentDate', label: 'Payment Date', type: 'date' },
    ],
  },
  {
    key: 'EXPENSES',
    label: 'Operational Expenses',
    fields: [
      { key: 'voucherNo', label: 'Voucher No', type: 'text' },
      { key: 'category', label: 'Category', type: 'text' },
      { key: 'description', label: 'Description', type: 'text' },
      { key: 'amount', label: 'Amount (INR)', type: 'currency' },
      { key: 'status', label: 'Status', type: 'status' },
      { key: 'expenseDate', label: 'Expense Date', type: 'date' },
    ],
  },
  {
    key: 'JOURNAL_VOUCHERS',
    label: 'Payroll & Journal Runs',
    fields: [
      { key: 'runId', label: 'Voucher / Run ID', type: 'text' },
      { key: 'monthCode', label: 'Period', type: 'text' },
      { key: 'voucherNo', label: 'GL Voucher No', type: 'text' },
      { key: 'employeeCount', label: 'Staff Count', type: 'number' },
      { key: 'totalGross', label: 'Gross Amount (INR)', type: 'currency' },
      { key: 'totalNet', label: 'Net Amount (INR)', type: 'currency' },
      { key: 'status', label: 'Status', type: 'status' },
      { key: 'postedDate', label: 'Posted Date', type: 'date' },
    ],
  },
  {
    key: 'SERVICES',
    label: 'Service Catalog & Rates',
    fields: [
      { key: 'serviceCode', label: 'Service Code', type: 'text' },
      { key: 'name', label: 'Service Name', type: 'text' },
      { key: 'categoryName', label: 'Category', type: 'text' },
      { key: 'govtFee', label: 'Govt Fee (INR)', type: 'currency' },
      { key: 'serviceCharge', label: 'Service Charge (INR)', type: 'currency' },
      { key: 'totalFee', label: 'Total Rate (INR)', type: 'currency' },
      { key: 'status', label: 'Status', type: 'status' },
    ],
  },
  {
    key: 'PRODUCTS_STOCK',
    label: 'Products & Inventory Stock',
    fields: [
      { key: 'sku', label: 'SKU / Code', type: 'text' },
      { key: 'name', label: 'Product Name', type: 'text' },
      { key: 'category', label: 'Category', type: 'text' },
      { key: 'stockQty', label: 'Stock Qty', type: 'number' },
      { key: 'unitPrice', label: 'Unit Price (INR)', type: 'currency' },
      { key: 'stockValue', label: 'Stock Value (INR)', type: 'currency' },
      { key: 'status', label: 'Status', type: 'status' },
    ],
  },
  {
    key: 'EMPLOYEES_PAYROLL',
    label: 'Employees & Payroll Master',
    fields: [
      { key: 'empId', label: 'Employee ID', type: 'text' },
      { key: 'fullName', label: 'Employee Name', type: 'text' },
      { key: 'designation', label: 'Designation', type: 'text' },
      { key: 'department', label: 'Department', type: 'text' },
      { key: 'mobile', label: 'Mobile', type: 'text' },
      { key: 'basicSalary', label: 'Basic Salary (INR)', type: 'currency' },
      { key: 'netSalary', label: 'Net Salary (INR)', type: 'currency' },
      { key: 'status', label: 'Status', type: 'status' },
    ],
  },
];

// Safe arithmetic expression parser for calculated columns ([fieldA] - [fieldB]) — zero eval()
function evaluateSafeFormula(
  expression: string,
  row: Record<string, string | number | boolean | null>
): number {
  const substituted = expression.replace(/\[([a-zA-Z0-9_]+)\]/g, (_m, key: string) => {
    const num = Number(row[key] ?? 0);
    return Number.isFinite(num) ? String(num) : '0';
  });
  const tokens: string[] = [];
  let i = 0;
  while (i < substituted.length) {
    const ch = substituted[i];
    if (/\s/.test(ch)) {
      i += 1;
      continue;
    }
    if ('+-*/()%'.includes(ch)) {
      tokens.push(ch);
      i += 1;
      continue;
    }
    if (/[0-9.]/.test(ch)) {
      let numStr = '';
      while (i < substituted.length && /[0-9.]/.test(substituted[i])) {
        numStr += substituted[i];
        i += 1;
      }
      tokens.push(numStr);
      continue;
    }
    return 0;
  }

  let pos = 0;
  function parseExpr(): number {
    let left = parseTerm();
    while (pos < tokens.length && (tokens[pos] === '+' || tokens[pos] === '-')) {
      const op = tokens[pos++];
      const right = parseTerm();
      left = op === '+' ? left + right : left - right;
    }
    return left;
  }
  function parseTerm(): number {
    let left = parseFactor();
    while (pos < tokens.length && (tokens[pos] === '*' || tokens[pos] === '/' || tokens[pos] === '%')) {
      const op = tokens[pos++];
      const right = parseFactor();
      if (op === '*') left *= right;
      else if (op === '/') left = right === 0 ? 0 : left / right;
      else left = right === 0 ? 0 : left % right;
    }
    return left;
  }
  function parseFactor(): number {
    if (tokens[pos] === '-') {
      pos += 1;
      return -parseFactor();
    }
    if (tokens[pos] === '(') {
      pos += 1;
      const val = parseExpr();
      if (tokens[pos] === ')') pos += 1;
      return val;
    }
    const tok = tokens[pos++];
    const n = Number(tok);
    return Number.isFinite(n) ? n : 0;
  }

  const result = parseExpr();
  return Number.isFinite(result) ? Number(result.toFixed(2)) : 0;
}

async function safeListCollection(name: string): Promise<Array<Record<string, unknown>>> {
  if (!db) return [];
  try {
    const snap = await getDocs(collection(db, name));
    return snap.docs.map((d) => ({ id: d.id, ...(d.data() as Record<string, unknown>) }));
  } catch {
    return [];
  }
}

export async function recordReportAuditLog(params: {
  actor: ReportsActorContext;
  action: string;
  reportName: string;
  reportCategory: string;
  exportFormat?: string;
  filtersSnapshot?: Record<string, unknown>;
  dateRangeLabel?: string;
  status?: 'SUCCESS' | 'FAILURE' | 'BLOCKED';
}): Promise<ReportAuditLogItem> {
  const { db: firestore, uid } = requireDb();
  const docId = `RLOG-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
  const nowIso = new Date().toISOString();
  const payload = {
    docId,
    id: Date.now(),
    actorUserId: params.actor.userId,
    actorRole: params.actor.role,
    action: params.action,
    reportName: params.reportName,
    reportCategory: params.reportCategory,
    filtersSnapshot: params.filtersSnapshot || {},
    dateRangeLabel: params.dateRangeLabel || 'All Dates',
    exportFormat: params.exportFormat || 'VIEW',
    status: params.status || 'SUCCESS',
    ipAddress: 'Direct-Firebase-TLS',
    createdAtIso: nowIso,
    createdByUid: uid,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp(),
  };

  try {
    await setDoc(doc(firestore, 'reportAuditLogs', docId), payload);
  } catch {
    // Non-blocking audit log write
  }

  return {
    id: payload.id,
    actorUserId: payload.actorUserId,
    actorRole: payload.actorRole,
    action: payload.action,
    reportName: payload.reportName,
    reportCategory: payload.reportCategory,
    filtersSnapshot: payload.filtersSnapshot,
    dateRangeLabel: payload.dateRangeLabel,
    exportFormat: payload.exportFormat,
    status: payload.status,
    ipAddress: payload.ipAddress,
    createdAt: nowIso,
  };
}

export async function saveReportArchiveRecord(params: {
  actor: ReportsActorContext;
  reportKey: string;
  reportTitle: string;
  category: ReportDataset['category'];
  financialYear: string;
  exportFormat: 'PDF' | 'XLSX' | 'CSV';
  rowCount: number;
  fileSizeBytes: number;
}): Promise<ReportArchiveItem> {
  const { db: firestore, uid } = requireDb();
  const archiveCode = `ARC-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
  const nowIso = new Date().toISOString();
  const retentionUntil = new Date(Date.now() + 365 * 86400 * 1000).toISOString().slice(0, 10);
  const checksumSha256 = await sha256Hex(`${archiveCode}:${params.reportKey}:${params.rowCount}:${nowIso}`);

  const record: ReportArchiveItem = {
    id: Date.now(),
    archiveCode,
    reportKey: params.reportKey,
    reportTitle: params.reportTitle,
    category: params.category,
    financialYear: params.financialYear || currentFinancialYear(),
    exportFormat: params.exportFormat,
    versionNo: 1,
    rowCount: params.rowCount,
    checksumSha256,
    fileSizeBytes: params.fileSizeBytes,
    passwordProtected: false,
    retentionDays: 365,
    retentionUntil,
    deletionStatus: 'ACTIVE',
    deletionRequestedBy: null,
    deletionReason: null,
    deletionApprovedBy: null,
    generatedBy: params.actor.userId,
    generatedRole: params.actor.role,
    createdAt: nowIso,
  };

  await setDoc(doc(firestore, 'reportArchives', archiveCode), {
    ...record,
    docId: archiveCode,
    createdByUid: uid,
    createdAtIso: nowIso,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp(),
  });

  await recordReportAuditLog({
    actor: params.actor,
    action: `EXPORT_${params.exportFormat}`,
    reportName: params.reportTitle,
    reportCategory: params.category,
    exportFormat: params.exportFormat,
    dateRangeLabel: `FY ${record.financialYear}`,
  });

  return record;
}

function matchesDateAndSearch(
  dateStr: string,
  rowObj: Record<string, unknown>,
  filters: ReportFilterInput
): boolean {
  if (filters.fromDate && dateStr && dateStr < filters.fromDate) return false;
  if (filters.toDate && dateStr && dateStr > filters.toDate) return false;
  if (filters.status && filters.status !== 'ALL') {
    const s = String(rowObj.status || rowObj.verificationStatus || rowObj.applicationStatus || '');
    if (s.toUpperCase() !== filters.status.toUpperCase()) return false;
  }
  if (filters.search) {
    const q = filters.search.toLowerCase();
    const hay = Object.values(rowObj).map((v) => String(v ?? '').toLowerCase()).join(' ');
    if (!hay.includes(q)) return false;
  }
  return true;
}

const REPORT_KEY_ALIASES: Record<string, string> = {
  CUST_COMPLETE_LIST: 'CUSTOMER_LIST',
  CUST_VILLAGE_WISE: 'CUSTOMER_LIST',
  APP_TOTAL_REPORT: 'APPLICATIONS_MASTER',
  APP_COLLECTION_REPORT: 'INCOME_LEDGER',
  FIN_PNL_STATEMENT: 'PROFIT_LOSS_STATEMENT',
  FIN_BALANCE_SHEET: 'PROFIT_LOSS_STATEMENT',
  FIN_CLOSING_BALANCE: 'INCOME_LEDGER',
  CSC_DAILY_OPERATIONS: 'CSC_ORDERS_REPORT',
};

export async function buildReportDataset(
  rawReportKey: string,
  filters: ReportFilterInput,
  actor: ReportsActorContext
): Promise<ReportDataset> {
  const reportKey = REPORT_KEY_ALIASES[rawReportKey] || rawReportKey;
  const fy = filters.financialYear || currentFinancialYear();
  const dateRangeLabel =
    filters.fromDate && filters.toDate
      ? `${filters.fromDate} to ${filters.toDate}`
      : filters.fromDate
        ? `From ${filters.fromDate}`
        : filters.toDate
          ? `Up to ${filters.toDate}`
          : `FY ${fy}`;

  const meta = REPORT_CATALOG_LIST.find((r) => r.reportKey === reportKey) || {
    reportKey,
    title: reportKey.replace(/_/g, ' '),
    titleBn: '',
    category: 'CUSTOM' as const,
    description: 'Live Firestore report dataset',
  };

  let columns: ReportColumnDef[] = [];
  let rows: Array<Record<string, string | number | boolean | null>> = [];
  const totals: Record<string, string | number> = {};
  let summaryCards: Array<{ label: string; value: string; note?: string }> = [];

  if (reportKey === 'CUSTOMER_LIST' || reportKey === 'CUSTOMER_DUES') {
    const [customers, apps] = await Promise.all([
      safeListCollection('customers'),
      safeListCollection('applications'),
    ]);
    const appTotalsByCust = new Map<string, { apps: number; billed: number; paid: number; due: number }>();
    apps.forEach((a) => {
      const cid = String(a.customerId || '');
      const fin = (a.financialSummary || {}) as Record<string, unknown>;
      const total = Number(fin.totalAmount ?? a.totalFee ?? 0);
      const paid = Number(fin.paidAmount ?? a.paidAmount ?? 0);
      const due = Math.max(0, total - paid);
      const prev = appTotalsByCust.get(cid) || { apps: 0, billed: 0, paid: 0, due: 0 };
      appTotalsByCust.set(cid, {
        apps: prev.apps + 1,
        billed: prev.billed + total,
        paid: prev.paid + paid,
        due: prev.due + due,
      });
    });

    columns = [
      { key: 'customerId', label: 'Customer ID', type: 'text' },
      { key: 'fullName', label: 'Full Name', type: 'text' },
      { key: 'mobile', label: 'Mobile', type: 'text' },
      { key: 'village', label: 'Village / Town', type: 'text' },
      { key: 'segment', label: 'Segment', type: 'text' },
      { key: 'appsCount', label: 'Apps', type: 'number', align: 'right' },
      { key: 'billed', label: 'Total Billed', type: 'currency', align: 'right' },
      { key: 'paid', label: 'Paid', type: 'currency', align: 'right' },
      { key: 'due', label: 'Due Balance', type: 'currency', align: 'right' },
      { key: 'status', label: 'Status', type: 'status' },
    ];

    const filtered = customers.filter((c) => {
      const d = toIsoDate(c.createdAt);
      if (!matchesDateAndSearch(d, c, filters)) return false;
      if (filters.location) {
        const loc = `${c.village || ''} ${c.district || ''}`.toLowerCase();
        if (!loc.includes(filters.location.toLowerCase())) return false;
      }
      if (reportKey === 'CUSTOMER_DUES') {
        const stats = appTotalsByCust.get(String(c.customerId || c.id || ''));
        return Boolean(stats && stats.due > 0);
      }
      return true;
    });

    rows = filtered.map((c) => {
      const cid = String(c.customerId || c.id || '');
      const stats = appTotalsByCust.get(cid) || { apps: 0, billed: 0, paid: 0, due: 0 };
      return {
        customerId: cid,
        fullName: String(c.fullName || ''),
        mobile: String(c.mobile || ''),
        village: String(c.village || ''),
        segment: String(c.segment || 'Individual'),
        appsCount: stats.apps,
        billed: stats.billed,
        paid: stats.paid,
        due: stats.due,
        status: String(c.status || 'Active'),
      };
    });

    totals.appsCount = rows.reduce((s, r) => s + Number(r.appsCount || 0), 0);
    totals.billed = rows.reduce((s, r) => s + Number(r.billed || 0), 0);
    totals.paid = rows.reduce((s, r) => s + Number(r.paid || 0), 0);
    totals.due = rows.reduce((s, r) => s + Number(r.due || 0), 0);
    summaryCards = [
      { label: 'Total Customers', value: String(rows.length) },
      { label: 'Total Billed', value: `₹${Number(totals.billed).toLocaleString('en-IN')}` },
      { label: 'Total Due', value: `₹${Number(totals.due).toLocaleString('en-IN')}` },
    ];
  } else if (reportKey === 'APPLICATIONS_MASTER') {
    const apps = await safeListCollection('applications');
    columns = [
      { key: 'applicationNo', label: 'Application No', type: 'text' },
      { key: 'customerName', label: 'Customer Name', type: 'text' },
      { key: 'serviceName', label: 'Service', type: 'text' },
      { key: 'status', label: 'Status', type: 'status' },
      { key: 'assignedStaffId', label: 'Staff ID', type: 'text' },
      { key: 'totalFee', label: 'Total Fee', type: 'currency', align: 'right' },
      { key: 'paidAmount', label: 'Paid', type: 'currency', align: 'right' },
      { key: 'dueAmount', label: 'Due', type: 'currency', align: 'right' },
      { key: 'applicationDate', label: 'Date', type: 'date' },
    ];

    rows = apps
      .filter((a) => matchesDateAndSearch(String(a.applicationDate || toIsoDate(a.createdAt)), a, filters))
      .map((a) => {
        const fin = (a.financialSummary || {}) as Record<string, unknown>;
        const total = Number(fin.totalAmount ?? a.totalFee ?? 0);
        const paid = Number(fin.paidAmount ?? a.paidAmount ?? 0);
        return {
          applicationNo: String(a.applicationNo || a.id || ''),
          customerName: String(a.customerName || ''),
          serviceName: String(a.serviceName || ''),
          status: String(a.status || 'Draft'),
          assignedStaffId: String(a.assignedStaffId || 'Unassigned'),
          totalFee: total,
          paidAmount: paid,
          dueAmount: Math.max(0, total - paid),
          applicationDate: String(a.applicationDate || toIsoDate(a.createdAt)),
        };
      });

    totals.totalFee = rows.reduce((s, r) => s + Number(r.totalFee || 0), 0);
    totals.paidAmount = rows.reduce((s, r) => s + Number(r.paidAmount || 0), 0);
    totals.dueAmount = rows.reduce((s, r) => s + Number(r.dueAmount || 0), 0);
    summaryCards = [
      { label: 'Applications', value: String(rows.length) },
      { label: 'Fees Billed', value: `₹${Number(totals.totalFee).toLocaleString('en-IN')}` },
      { label: 'Collected', value: `₹${Number(totals.paidAmount).toLocaleString('en-IN')}` },
    ];
  } else if (reportKey === 'SERVICE_WISE_REVENUE') {
    const apps = await safeListCollection('applications');
    const grouped = new Map<string, { serviceName: string; count: number; totalFee: number; paid: number; due: number }>();
    apps
      .filter((a) => matchesDateAndSearch(String(a.applicationDate || toIsoDate(a.createdAt)), a, filters))
      .forEach((a) => {
        const sName = String(a.serviceName || 'General Service');
        const fin = (a.financialSummary || {}) as Record<string, unknown>;
        const total = Number(fin.totalAmount ?? a.totalFee ?? 0);
        const paid = Number(fin.paidAmount ?? a.paidAmount ?? 0);
        const cur = grouped.get(sName) || { serviceName: sName, count: 0, totalFee: 0, paid: 0, due: 0 };
        cur.count += 1;
        cur.totalFee += total;
        cur.paid += paid;
        cur.due += Math.max(0, total - paid);
        grouped.set(sName, cur);
      });
    columns = [
      { key: 'serviceName', label: 'Service Name', type: 'text' },
      { key: 'count', label: 'Volume', type: 'number', align: 'right' },
      { key: 'totalFee', label: 'Total Billed', type: 'currency', align: 'right' },
      { key: 'paid', label: 'Collected', type: 'currency', align: 'right' },
      { key: 'due', label: 'Due', type: 'currency', align: 'right' },
    ];
    rows = Array.from(grouped.values()).sort((a, b) => b.totalFee - a.totalFee);
    totals.count = rows.reduce((s, r) => s + Number(r.count || 0), 0);
    totals.totalFee = rows.reduce((s, r) => s + Number(r.totalFee || 0), 0);
    totals.paid = rows.reduce((s, r) => s + Number(r.paid || 0), 0);
    totals.due = rows.reduce((s, r) => s + Number(r.due || 0), 0);
  } else if (reportKey === 'STAFF_PERFORMANCE') {
    const [apps, payments] = await Promise.all([
      safeListCollection('applications'),
      safeListCollection('payments'),
    ]);
    const map = new Map<string, { staffId: string; total: number; completed: number; pending: number; collections: number }>();
    apps.forEach((a) => {
      const sid = String(a.assignedStaffId || a.createdBy || 'UNASSIGNED');
      const cur = map.get(sid) || { staffId: sid, total: 0, completed: 0, pending: 0, collections: 0 };
      cur.total += 1;
      if (a.status === 'Completed') cur.completed += 1;
      else if (a.status !== 'Cancelled' && a.status !== 'Rejected') cur.pending += 1;
      map.set(sid, cur);
    });
    payments.forEach((p) => {
      if (p.verificationStatus !== 'Confirmed') return;
      const sid = String(p.collectedBy || 'UNASSIGNED');
      const cur = map.get(sid) || { staffId: sid, total: 0, completed: 0, pending: 0, collections: 0 };
      cur.collections += Number(p.amount || 0);
      map.set(sid, cur);
    });
    columns = [
      { key: 'staffId', label: 'Operator / Staff ID', type: 'text' },
      { key: 'total', label: 'Assigned Apps', type: 'number', align: 'right' },
      { key: 'completed', label: 'Completed', type: 'number', align: 'right' },
      { key: 'pending', label: 'Pending', type: 'number', align: 'right' },
      { key: 'completionPct', label: 'Success %', type: 'number', align: 'right' },
      { key: 'collections', label: 'Collections', type: 'currency', align: 'right' },
    ];
    rows = Array.from(map.values()).map((r) => ({
      ...r,
      completionPct: r.total > 0 ? Math.round((r.completed / r.total) * 100) : 0,
    }));
    totals.total = rows.reduce((s, r) => s + Number(r.total || 0), 0);
    totals.completed = rows.reduce((s, r) => s + Number(r.completed || 0), 0);
    totals.collections = rows.reduce((s, r) => s + Number(r.collections || 0), 0);
  } else if (reportKey === 'INCOME_LEDGER') {
    const payments = await safeListCollection('payments');
    columns = [
      { key: 'transactionId', label: 'Transaction ID', type: 'text' },
      { key: 'receiptNo', label: 'Receipt No', type: 'text' },
      { key: 'applicationNo', label: 'Application No', type: 'text' },
      { key: 'paymentMethod', label: 'Method', type: 'text' },
      { key: 'amount', label: 'Amount', type: 'currency', align: 'right' },
      { key: 'verificationStatus', label: 'Status', type: 'status' },
      { key: 'paymentDate', label: 'Date', type: 'date' },
    ];
    rows = payments
      .filter((p) => {
        if (filters.paymentMethod && filters.paymentMethod !== 'ALL' && p.paymentMethod !== filters.paymentMethod) {
          return false;
        }
        return matchesDateAndSearch(String(p.paymentDate || toIsoDate(p.createdAt)), p, filters);
      })
      .map((p) => ({
        transactionId: String(p.transactionId || p.id || ''),
        receiptNo: String(p.receiptNo || ''),
        applicationNo: String(p.applicationNo || ''),
        paymentMethod: String(p.paymentMethod || 'Cash'),
        amount: Number(p.amount || 0),
        verificationStatus: String(p.verificationStatus || 'Confirmed'),
        paymentDate: String(p.paymentDate || toIsoDate(p.createdAt)),
      }));
    totals.amount = rows.reduce((s, r) => s + Number(r.amount || 0), 0);
  } else if (reportKey === 'EXPENSE_LEDGER') {
    const expenses = await safeListCollection('expenses');
    columns = [
      { key: 'voucherNo', label: 'Voucher No', type: 'text' },
      { key: 'category', label: 'Category', type: 'text' },
      { key: 'description', label: 'Description', type: 'text' },
      { key: 'amount', label: 'Amount', type: 'currency', align: 'right' },
      { key: 'status', label: 'Status', type: 'status' },
      { key: 'expenseDate', label: 'Date', type: 'date' },
    ];
    rows = expenses
      .filter((e) => matchesDateAndSearch(String(e.expenseDate || toIsoDate(e.createdAt)), e, filters))
      .map((e) => ({
        voucherNo: String(e.voucherNo || e.id || ''),
        category: String(e.category || 'General'),
        description: String(e.description || ''),
        amount: Number(e.amount || 0),
        status: String(e.status || 'Approved'),
        expenseDate: String(e.expenseDate || toIsoDate(e.createdAt)),
      }));
    totals.amount = rows.reduce((s, r) => s + Number(r.amount || 0), 0);
  } else if (reportKey === 'PROFIT_LOSS_STATEMENT') {
    const [payments, expenses, refunds] = await Promise.all([
      safeListCollection('payments'),
      safeListCollection('expenses'),
      safeListCollection('refunds'),
    ]);
    const income = payments
      .filter((p) => p.verificationStatus === 'Confirmed' && matchesDateAndSearch(String(p.paymentDate || toIsoDate(p.createdAt)), p, filters))
      .reduce((s, p) => s + Number(p.amount || 0), 0);
    const expenseTotal = expenses
      .filter((e) => matchesDateAndSearch(String(e.expenseDate || toIsoDate(e.createdAt)), e, filters))
      .reduce((s, e) => s + Number(e.amount || 0), 0);
    const refundTotal = refunds
      .filter((r) => r.status === 'Processed')
      .reduce((s, r) => s + Number(r.refundAmount || 0), 0);
    const netProfit = income - expenseTotal - refundTotal;
    columns = [
      { key: 'head', label: 'Account Head', type: 'text' },
      { key: 'type', label: 'Classification', type: 'text' },
      { key: 'amount', label: 'Amount (INR)', type: 'currency', align: 'right' },
    ];
    rows = [
      { head: 'Confirmed Service & Counter Collections', type: 'INCOME', amount: income },
      { head: 'Approved Operational Expenses', type: 'EXPENSE', amount: expenseTotal },
      { head: 'Processed Customer Refunds', type: 'DEDUCTION', amount: refundTotal },
      { head: 'Net Operating Profit / Surplus', type: netProfit >= 0 ? 'NET PROFIT' : 'NET DEFICIT', amount: netProfit },
    ];
    totals.amount = netProfit;
  } else if (reportKey === 'PRODUCTS_STOCK_REPORT') {
    const products = await safeListCollection('products');
    columns = [
      { key: 'sku', label: 'SKU', type: 'text' },
      { key: 'name', label: 'Product Name', type: 'text' },
      { key: 'category', label: 'Category', type: 'text' },
      { key: 'stockQty', label: 'Stock Qty', type: 'number', align: 'right' },
      { key: 'unitPrice', label: 'Unit Price', type: 'currency', align: 'right' },
      { key: 'stockValue', label: 'Stock Value', type: 'currency', align: 'right' },
      { key: 'status', label: 'Status', type: 'status' },
    ];
    rows = products.map((p) => {
      const qty = Number(p.stockQty ?? p.quantity ?? 0);
      const price = Number(p.sellingPrice ?? p.unitPrice ?? 0);
      return {
        sku: String(p.sku || p.productCode || p.id || ''),
        name: String(p.name || ''),
        category: String(p.category || 'Retail'),
        stockQty: qty,
        unitPrice: price,
        stockValue: qty * price,
        status: String(p.status || 'Active'),
      };
    });
    totals.stockQty = rows.reduce((s, r) => s + Number(r.stockQty || 0), 0);
    totals.stockValue = rows.reduce((s, r) => s + Number(r.stockValue || 0), 0);
  } else if (reportKey === 'EMPLOYEE_PAYROLL_REPORT') {
    const employees = await safeListCollection('employees');
    columns = [
      { key: 'empId', label: 'Emp ID', type: 'text' },
      { key: 'fullName', label: 'Name', type: 'text' },
      { key: 'designation', label: 'Designation', type: 'text' },
      { key: 'department', label: 'Department', type: 'text' },
      { key: 'mobile', label: 'Mobile', type: 'text' },
      { key: 'basicSalary', label: 'Basic', type: 'currency', align: 'right' },
      { key: 'netSalary', label: 'Net Pay', type: 'currency', align: 'right' },
      { key: 'status', label: 'Status', type: 'status' },
    ];
    rows = employees.map((e) => ({
      empId: String(e.empId || e.id || ''),
      fullName: String(e.fullName || ''),
      designation: String(e.designation || ''),
      department: String(e.department || 'Operations'),
      mobile: String(e.mobile || ''),
      basicSalary: Number(e.basicSalary || 0),
      netSalary: Number(e.netSalary || 0),
      status: String(e.status || 'Active'),
    }));
    totals.basicSalary = rows.reduce((s, r) => s + Number(r.basicSalary || 0), 0);
    totals.netSalary = rows.reduce((s, r) => s + Number(r.netSalary || 0), 0);
  } else if (reportKey === 'CSC_ORDERS_REPORT') {
    const orders = await safeListCollection('cscOrders');
    columns = [
      { key: 'orderId', label: 'Order ID', type: 'text' },
      { key: 'customerName', label: 'Citizen Name', type: 'text' },
      { key: 'selectedServiceName', label: 'Service', type: 'text' },
      { key: 'applicationStatus', label: 'Status', type: 'status' },
      { key: 'totalAmount', label: 'Total', type: 'currency', align: 'right' },
      { key: 'totalPaid', label: 'Paid', type: 'currency', align: 'right' },
      { key: 'remainingDue', label: 'Due', type: 'currency', align: 'right' },
      { key: 'orderDate', label: 'Date', type: 'date' },
    ];
    rows = orders.map((o) => ({
      orderId: String(o.orderId || o.id || ''),
      customerName: String(o.customerName || ''),
      selectedServiceName: String(o.selectedServiceName || ''),
      applicationStatus: String(o.applicationStatus || 'Pending'),
      totalAmount: Number(o.totalAmount || 0),
      totalPaid: Number(o.totalPaid || 0),
      remainingDue: Number(o.remainingDue || 0),
      orderDate: String(o.orderDate || toIsoDate(o.createdAt)),
    }));
    totals.totalAmount = rows.reduce((s, r) => s + Number(r.totalAmount || 0), 0);
    totals.totalPaid = rows.reduce((s, r) => s + Number(r.totalPaid || 0), 0);
    totals.remainingDue = rows.reduce((s, r) => s + Number(r.remainingDue || 0), 0);
  } else if (reportKey === 'PVC_PRINTING_REPORT') {
    const pvcOrders = await safeListCollection('pvcOrders');
    columns = [
      { key: 'orderId', label: 'Order ID', type: 'text' },
      { key: 'customerName', label: 'Customer / Shop', type: 'text' },
      { key: 'orderType', label: 'Order Type', type: 'text' },
      { key: 'quantity', label: 'Cards Qty', type: 'number', align: 'right' },
      { key: 'grandTotal', label: 'Grand Total', type: 'currency', align: 'right' },
      { key: 'totalPaid', label: 'Paid', type: 'currency', align: 'right' },
      { key: 'status', label: 'Status', type: 'status' },
    ];
    rows = pvcOrders.map((p) => ({
      orderId: String(p.orderId || p.id || ''),
      customerName: String(p.customerName || p.shopName || ''),
      orderType: String(p.orderType || 'Individual'),
      quantity: Number(p.quantity || 1),
      grandTotal: Number(p.grandTotal || 0),
      totalPaid: Number(p.totalPaid || 0),
      status: String(p.status || 'Completed'),
    }));
    totals.quantity = rows.reduce((s, r) => s + Number(r.quantity || 0), 0);
    totals.grandTotal = rows.reduce((s, r) => s + Number(r.grandTotal || 0), 0);
    totals.totalPaid = rows.reduce((s, r) => s + Number(r.totalPaid || 0), 0);
  } else {
    // GRIEVANCE_RTI_REPORT or fallback
    const grievances = await safeListCollection('cscGrievances');
    columns = [
      { key: 'internalTrackingId', label: 'Tracking ID', type: 'text' },
      { key: 'customerName', label: 'Citizen Name', type: 'text' },
      { key: 'mobile', label: 'Mobile', type: 'text' },
      { key: 'department', label: 'Department', type: 'text' },
      { key: 'complaintSubject', label: 'Subject', type: 'text' },
      { key: 'status', label: 'Status', type: 'status' },
    ];
    rows = grievances.map((g) => ({
      internalTrackingId: String(g.internalTrackingId || g.id || ''),
      customerName: String(g.customerName || ''),
      mobile: String(g.mobile || ''),
      department: String(g.department || ''),
      complaintSubject: String(g.complaintSubject || ''),
      status: String(g.status || 'Open'),
    }));
  }

  const totalRowsBeforeLimit = rows.length;
  if (filters.limit && filters.limit > 0) {
    rows = rows.slice(0, filters.limit);
  }

  await recordReportAuditLog({
    actor,
    action: 'GENERATE_REPORT',
    reportName: meta.title,
    reportCategory: meta.category,
    exportFormat: 'VIEW',
    filtersSnapshot: filters as Record<string, unknown>,
    dateRangeLabel,
  });

  return {
    reportKey,
    title: meta.title,
    titleBn: meta.titleBn,
    subtitle: meta.description,
    category: meta.category,
    financialYear: fy,
    dateRangeLabel,
    generatedAt: new Date().toISOString(),
    generatedBy: actor.userId,
    columns,
    rows,
    totals,
    summaryCards,
    totalRowsBeforeLimit,
  };
}

function matchesCustomCondition(
  row: Record<string, string | number | boolean | null>,
  rule: CustomFilterRule
): boolean {
  const raw = row[rule.field];
  const leftStr = String(raw ?? '').toLowerCase();
  const rightStr = String(rule.value ?? '').toLowerCase();
  const leftNum = Number(raw);
  const rightNum = Number(rule.value);

  switch (rule.operator) {
    case 'eq':
      return leftStr === rightStr;
    case 'neq':
      return leftStr !== rightStr;
    case 'contains':
      return leftStr.includes(rightStr);
    case 'gt':
      return Number.isFinite(leftNum) && Number.isFinite(rightNum) && leftNum > rightNum;
    case 'gte':
      return Number.isFinite(leftNum) && Number.isFinite(rightNum) && leftNum >= rightNum;
    case 'lt':
      return Number.isFinite(leftNum) && Number.isFinite(rightNum) && leftNum < rightNum;
    case 'lte':
      return Number.isFinite(leftNum) && Number.isFinite(rightNum) && leftNum <= rightNum;
    default:
      return true;
  }
}

async function loadDataSourceRows(
  dataSource: BuilderDataSourceKey
): Promise<Array<Record<string, string | number | boolean | null>>> {
  if (dataSource === 'CUSTOMERS') {
    const list = await safeListCollection('customers');
    return list.map((c) => ({
      customerId: String(c.customerId || c.id || ''),
      fullName: String(c.fullName || ''),
      mobile: String(c.mobile || ''),
      village: String(c.village || ''),
      district: String(c.district || ''),
      segment: String(c.segment || 'Individual'),
      status: String(c.status || 'Active'),
      createdDate: toIsoDate(c.createdAt),
    }));
  }
  if (dataSource === 'APPLICATIONS') {
    const list = await safeListCollection('applications');
    return list.map((a) => {
      const fin = (a.financialSummary || {}) as Record<string, unknown>;
      const total = Number(fin.totalAmount ?? a.totalFee ?? 0);
      const paid = Number(fin.paidAmount ?? a.paidAmount ?? 0);
      return {
        applicationNo: String(a.applicationNo || a.id || ''),
        customerName: String(a.customerName || ''),
        serviceName: String(a.serviceName || ''),
        status: String(a.status || 'Draft'),
        assignedStaffId: String(a.assignedStaffId || 'Unassigned'),
        totalFee: total,
        paidAmount: paid,
        dueAmount: Math.max(0, total - paid),
        applicationDate: String(a.applicationDate || toIsoDate(a.createdAt)),
      };
    });
  }
  if (dataSource === 'PAYMENTS') {
    const list = await safeListCollection('payments');
    return list.map((p) => ({
      transactionId: String(p.transactionId || p.id || ''),
      receiptNo: String(p.receiptNo || ''),
      applicationNo: String(p.applicationNo || ''),
      paymentMethod: String(p.paymentMethod || 'Cash'),
      amount: Number(p.amount || 0),
      verificationStatus: String(p.verificationStatus || 'Confirmed'),
      paymentDate: String(p.paymentDate || toIsoDate(p.createdAt)),
    }));
  }
  if (dataSource === 'EXPENSES') {
    const list = await safeListCollection('expenses');
    return list.map((e) => ({
      voucherNo: String(e.voucherNo || e.id || ''),
      category: String(e.category || 'General'),
      description: String(e.description || ''),
      amount: Number(e.amount || 0),
      status: String(e.status || 'Approved'),
      expenseDate: String(e.expenseDate || toIsoDate(e.createdAt)),
    }));
  }
  if (dataSource === 'JOURNAL_VOUCHERS') {
    const list = await safeListCollection('payrollRuns');
    return list.map((r) => ({
      runId: String(r.runId || r.id || ''),
      monthCode: String(r.monthCode || ''),
      voucherNo: String(r.voucherNo || ''),
      employeeCount: Number(r.employeeCount || 0),
      totalGross: Number(r.grossTotal ?? r.totalGross ?? 0),
      totalNet: Number(r.netPayableTotal ?? r.totalNet ?? 0),
      status: String(r.status || 'POSTED'),
      postedDate: toIsoDate(r.createdAt),
    }));
  }
  if (dataSource === 'SERVICES') {
    const list = await safeListCollection('services');
    return list.map((s) => ({
      serviceCode: String(s.serviceCode || s.serviceId || s.id || ''),
      name: String(s.name || ''),
      categoryName: String(s.categoryName || ''),
      govtFee: Number(s.govtFee || 0),
      serviceCharge: Number(s.serviceCharge || 0),
      totalFee: Number(s.totalFee ?? (Number(s.govtFee || 0) + Number(s.serviceCharge || 0))),
      status: String(s.status || 'Active'),
    }));
  }
  if (dataSource === 'PRODUCTS_STOCK') {
    const list = await safeListCollection('products');
    return list.map((p) => {
      const qty = Number(p.stockQty ?? p.quantity ?? 0);
      const price = Number(p.sellingPrice ?? p.unitPrice ?? 0);
      return {
        sku: String(p.sku || p.productCode || p.id || ''),
        name: String(p.name || ''),
        category: String(p.category || ''),
        stockQty: qty,
        unitPrice: price,
        stockValue: qty * price,
        status: String(p.status || 'Active'),
      };
    });
  }
  // EMPLOYEES_PAYROLL
  const list = await safeListCollection('employees');
  return list.map((e) => ({
    empId: String(e.empId || e.id || ''),
    fullName: String(e.fullName || ''),
    designation: String(e.designation || ''),
    department: String(e.department || 'Operations'),
    mobile: String(e.mobile || ''),
    basicSalary: Number(e.basicSalary || 0),
    netSalary: Number(e.netSalary || 0),
    status: String(e.status || 'Active'),
  }));
}

export async function executeCustomReportEngine(
  req: CustomReportExecutionRequest,
  actor: ReportsActorContext
): Promise<ReportDataset> {
  const schema = BUILDER_SCHEMAS.find((s) => s.key === req.dataSource) || BUILDER_SCHEMAS[0];
  let sourceRows = await loadDataSourceRows(req.dataSource);

  // Date filtering
  if (req.fromDate || req.toDate) {
    const dateKey =
      req.dateField ||
      schema.fields.find((f) => f.type === 'date')?.key ||
      '';
    if (dateKey) {
      sourceRows = sourceRows.filter((row) => {
        const d = String(row[dateKey] || '');
        if (!d) return true;
        if (req.fromDate && d < req.fromDate) return false;
        if (req.toDate && d > req.toDate) return false;
        return true;
      });
    }
  }

  // Keyword search
  if (req.search && req.search.trim()) {
    const q = req.search.trim().toLowerCase();
    sourceRows = sourceRows.filter((row) =>
      Object.values(row).some((v) => String(v ?? '').toLowerCase().includes(q))
    );
  }

  // Filter rules (AND / OR)
  if (Array.isArray(req.filters) && req.filters.length > 0) {
    const validFilters = req.filters.filter((f) => f.field && f.value !== '');
    if (validFilters.length > 0) {
      sourceRows = sourceRows.filter((row) =>
        req.filterLogic === 'OR'
          ? validFilters.some((f) => matchesCustomCondition(row, f))
          : validFilters.every((f) => matchesCustomCondition(row, f))
      );
    }
  }

  // Calculated formula columns
  const calcCols: CalculatedColumnRule[] = Array.isArray(req.calculatedColumns)
    ? req.calculatedColumns
    : [];
  const enrichedRows = sourceRows.map((row) => {
    const copy = { ...row };
    calcCols.forEach((calc) => {
      copy[calc.key] = evaluateSafeFormula(calc.expression, copy);
    });
    return copy;
  });

  // Sorting
  const sortField = req.sortByField;
  if (sortField) {
    const dir = req.sortDirection === 'asc' ? 1 : -1;
    enrichedRows.sort((a, b) => {
      const av = a[sortField];
      const bv = b[sortField];
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir;
      return String(av ?? '').localeCompare(String(bv ?? '')) * dir;
    });
  }

  const chosenFields = (req.selectedFields && req.selectedFields.length > 0
    ? req.selectedFields
    : schema.fields.map((f) => f.key)
  )
    .map((key) => schema.fields.find((f) => f.key === key))
    .filter((f): f is NonNullable<typeof f> => Boolean(f));

  const columns: ReportColumnDef[] = [
    ...chosenFields.map((f) => ({
      key: f.key,
      label: f.label,
      type: f.type,
      align: (f.type === 'number' || f.type === 'currency' ? 'right' : 'left') as 'right' | 'left',
    })),
    ...calcCols.map((c) => ({
      key: c.key,
      label: c.label,
      type: (c.format === 'currency' ? 'currency' : 'number') as 'currency' | 'number',
      align: 'right' as const,
    })),
  ];

  // Grouping with optional subtotals
  const numericCols = columns.filter((c) => c.type === 'number' || c.type === 'currency');
  let finalRows: Array<Record<string, string | number | boolean | null>> = [];

  if (req.groupByField) {
    const groups = new Map<string, Array<Record<string, string | number | boolean | null>>>();
    enrichedRows.forEach((row) => {
      const gKey = String(row[req.groupByField!] ?? 'Other');
      const arr = groups.get(gKey) || [];
      arr.push(row);
      groups.set(gKey, arr);
    });

    groups.forEach((groupRows, gKey) => {
      groupRows.forEach((r) => finalRows.push(r));
      if (req.includeSubtotals !== false) {
        const subRow: Record<string, string | number | boolean | null> = {};
        columns.forEach((c, idx) => {
          if (idx === 0) subRow[c.key] = `Subtotal: ${gKey} (${groupRows.length})`;
          else if (c.type === 'number' || c.type === 'currency') {
            subRow[c.key] = Number(
              groupRows.reduce((s, r) => s + Number(r[c.key] || 0), 0).toFixed(2)
            );
          } else {
            subRow[c.key] = '';
          }
        });
        finalRows.push(subRow);
      }
    });
  } else {
    finalRows = enrichedRows;
  }

  // Grand Totals
  const totals: Record<string, string | number> = {};
  if (req.includeGrandTotal !== false) {
    numericCols.forEach((c) => {
      totals[c.key] = Number(
        enrichedRows.reduce((s, r) => s + Number(r[c.key] || 0), 0).toFixed(2)
      );
    });
  }

  await recordReportAuditLog({
    actor,
    action: 'CUSTOM_BUILDER_PREVIEW',
    reportName: req.title || `Custom: ${schema.label}`,
    reportCategory: 'CUSTOM',
    exportFormat: 'PREVIEW',
  });

  return {
    reportKey: `CUSTOM_${req.dataSource}`,
    title: req.title || `Custom Report — ${schema.label}`,
    subtitle: `${schema.label} (${enrichedRows.length} matching records)`,
    category: 'CUSTOM',
    financialYear: currentFinancialYear(),
    dateRangeLabel: req.fromDate || req.toDate ? `${req.fromDate || 'Start'} to ${req.toDate || 'Now'}` : 'All Dates',
    generatedAt: new Date().toISOString(),
    generatedBy: actor.userId,
    columns,
    rows: finalRows,
    totals,
    summaryCards: [
      { label: 'Matching Records', value: String(enrichedRows.length) },
      { label: 'Columns Selected', value: String(columns.length) },
    ],
    totalRowsBeforeLimit: enrichedRows.length,
  };
}

export async function handleReportsRoute(
  path: string,
  method: string,
  body: Record<string, unknown>,
  actor: ReportsActorContext
): Promise<{ data: unknown; message?: string }> {
  const { db: firestore, uid } = requireDb();
  const [rawPath, rawQuery = ''] = path.split('?');
  const qs = new URLSearchParams(rawQuery);
  const nowIso = new Date().toISOString();

  // Dashboard
  if (rawPath === '/api/v1/reports/dashboard' && method === 'GET') {
    const [customers, apps, payments, expenses, logs] = await Promise.all([
      safeListCollection('customers'),
      safeListCollection('applications'),
      safeListCollection('payments'),
      safeListCollection('expenses'),
      safeListCollection('reportAuditLogs'),
    ]);

    const confirmedPayments = payments.filter((p) => p.verificationStatus === 'Confirmed');
    const totalIncome = confirmedPayments.reduce((s, p) => s + Number(p.amount || 0), 0);
    const totalExpenses = expenses.reduce((s, e) => s + Number(e.amount || 0), 0);
    const cash = confirmedPayments.filter((p) => p.paymentMethod === 'Cash').reduce((s, p) => s + Number(p.amount || 0), 0);
    const upi = confirmedPayments.filter((p) => p.paymentMethod === 'UPI').reduce((s, p) => s + Number(p.amount || 0), 0);
    const other = Math.max(0, totalIncome - cash - upi);

    let totalBilled = 0;
    let totalPaidApps = 0;
    let completed = 0;
    let rejected = 0;
    const staffMap = new Map<string, { total: number; completed: number; pending: number; collections: number }>();

    apps.forEach((a) => {
      const fin = (a.financialSummary || {}) as Record<string, unknown>;
      totalBilled += Number(fin.totalAmount ?? a.totalFee ?? 0);
      totalPaidApps += Number(fin.paidAmount ?? a.paidAmount ?? 0);
      if (a.status === 'Completed') completed += 1;
      else if (a.status === 'Cancelled' || a.status === 'Rejected') rejected += 1;

      const sid = String(a.assignedStaffId || a.createdBy || 'UNASSIGNED');
      const cur = staffMap.get(sid) || { total: 0, completed: 0, pending: 0, collections: 0 };
      cur.total += 1;
      if (a.status === 'Completed') cur.completed += 1;
      else if (a.status !== 'Cancelled' && a.status !== 'Rejected') cur.pending += 1;
      staffMap.set(sid, cur);
    });

    confirmedPayments.forEach((p) => {
      const sid = String(p.collectedBy || 'UNASSIGNED');
      const cur = staffMap.get(sid) || { total: 0, completed: 0, pending: 0, collections: 0 };
      cur.collections += Number(p.amount || 0);
      staffMap.set(sid, cur);
    });

    const pendingApps = Math.max(0, apps.length - completed - rejected);
    const successPct = apps.length > 0 ? Number(((completed / apps.length) * 100).toFixed(1)) : 0;

    const payload: ReportingDashboardData = {
      kpis: {
        totalReportsGenerated: logs.length,
        dailyReportsCount: logs.filter((l) => String(l.createdAtIso || '').slice(0, 10) === nowIso.slice(0, 10)).length,
        weeklyReportsCount: logs.length,
        monthlyReportsCount: logs.length,
        totalCustomers: customers.length,
        activeCustomers: customers.filter((c) => c.status === 'Active').length,
        totalApplications: apps.length,
        completedApplications: completed,
        pendingApplications: pendingApps,
        rejectedOrCancelledApplications: rejected,
        applicationSuccessRatePct: successPct,
        totalIncome,
        totalExpenses,
        netProfit: totalIncome - totalExpenses,
        totalCollections: totalIncome,
        outstandingCustomerDues: Math.max(0, totalBilled - totalPaidApps),
        paymentBreakdown: { cash, upi, other },
        growthIndicators: {
          customerGrowthPct: 0,
          applicationGrowthPct: 0,
          collectionGrowthPct: 0,
          methodologyNote: 'Computed directly from live Cloud Firestore collections.',
        },
      },
      staffPerformance: Array.from(staffMap.entries()).map(([staffId, v]) => ({
        staffId,
        staffName: staffId,
        totalAssigned: v.total,
        completed: v.completed,
        pending: v.pending,
        overdue: 0,
        completionRatePct: v.total > 0 ? Math.round((v.completed / v.total) * 100) : 0,
        collectionsHandled: v.collections,
      })),
      recentReportsActivity: logs
        .map((l) => ({
          id: Number(l.id || 0),
          actorUserId: String(l.actorUserId || ''),
          actorRole: String(l.actorRole || ''),
          action: String(l.action || ''),
          reportName: String(l.reportName || ''),
          reportCategory: String(l.reportCategory || ''),
          filtersSnapshot: (l.filtersSnapshot || {}) as Record<string, unknown>,
          dateRangeLabel: String(l.dateRangeLabel || ''),
          exportFormat: String(l.exportFormat || 'VIEW'),
          status: (l.status as 'SUCCESS' | 'FAILURE' | 'BLOCKED') || 'SUCCESS',
          ipAddress: String(l.ipAddress || 'Direct-Firebase-TLS'),
          createdAt: String(l.createdAtIso || toIsoTimestamp(l.createdAt)),
        }))
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
        .slice(0, 20),
      enabledBusinessModules: [
        { key: 'CSC_PORTAL', label: 'CSC Digital Operations', enabled: true, reason: 'Active' },
        { key: 'FINANCE_ENGINE', label: 'Double-Entry Finance', enabled: true, reason: 'Active' },
        { key: 'PAYROLL', label: 'Employees & Payroll', enabled: true, reason: 'Active' },
      ],
      financialYear: currentFinancialYear(),
    };
    return { data: payload };
  }

  // Catalog
  if (rawPath === '/api/v1/reports/catalog' && method === 'GET') {
    return { data: REPORT_CATALOG_LIST };
  }

  // Generate Dataset
  if (rawPath === '/api/v1/reports/generate' && method === 'POST') {
    const dataset = await buildReportDataset(
      String(body.reportKey || 'CUSTOMER_LIST'),
      (body.filters || {}) as ReportFilterInput,
      actor
    );
    return { data: dataset };
  }

  // Analytics
  if (rawPath === '/api/v1/reports/analytics' && method === 'GET') {
    const [customers, apps, payments, expenses] = await Promise.all([
      safeListCollection('customers'),
      safeListCollection('applications'),
      safeListCollection('payments'),
      safeListCollection('expenses'),
    ]);
    const granularity = (qs.get('granularity') || 'monthly') as AnalyticsDashboardPayload['granularity'];

    const monthIncome = new Map<string, number>();
    const monthExpense = new Map<string, number>();
    payments.filter((p) => p.verificationStatus === 'Confirmed').forEach((p) => {
      const m = String(p.paymentDate || toIsoDate(p.createdAt) || nowIso.slice(0, 10)).slice(0, 7);
      monthIncome.set(m, (monthIncome.get(m) || 0) + Number(p.amount || 0));
    });
    expenses.forEach((e) => {
      const m = String(e.expenseDate || toIsoDate(e.createdAt) || nowIso.slice(0, 10)).slice(0, 7);
      monthExpense.set(m, (monthExpense.get(m) || 0) + Number(e.amount || 0));
    });
    const months = Array.from(new Set([...monthIncome.keys(), ...monthExpense.keys()])).sort();
    if (months.length === 0) months.push(nowIso.slice(0, 7));

    const svcMap = new Map<string, { serviceId: string; serviceName: string; revenue: number; count: number }>();
    const statusMap = new Map<string, number>();
    apps.forEach((a) => {
      const st = String(a.status || 'Draft');
      statusMap.set(st, (statusMap.get(st) || 0) + 1);
      const sName = String(a.serviceName || 'General Service');
      const fin = (a.financialSummary || {}) as Record<string, unknown>;
      const rev = Number(fin.totalAmount ?? a.totalFee ?? 0);
      const cur = svcMap.get(sName) || { serviceId: String(a.serviceId || sName), serviceName: sName, revenue: 0, count: 0 };
      cur.revenue += rev;
      cur.count += 1;
      svcMap.set(sName, cur);
    });

    const totalApps = apps.length || 1;
    const fy = currentFinancialYear();
    const totalIncomeVal = Array.from(monthIncome.values()).reduce((s, n) => s + n, 0);
    const totalExpVal = Array.from(monthExpense.values()).reduce((s, n) => s + n, 0);

    const payload: AnalyticsDashboardPayload = {
      granularity,
      financialYear: fy,
      dateRangeLabel: `FY ${fy}`,
      revenueGrowth: months.map((m) => ({ label: m, value: monthIncome.get(m) || 0 })),
      incomeVsExpense: months.map((m) => ({ label: m, value: monthIncome.get(m) || 0, secondaryValue: monthExpense.get(m) || 0 })),
      profitTrend: months.map((m) => ({ label: m, value: (monthIncome.get(m) || 0) - (monthExpense.get(m) || 0) })),
      customerGrowth: months.map((m) => ({ label: m, value: customers.length })),
      applicationSuccessRate: Array.from(statusMap.entries()).map(([status, count]) => ({
        status,
        count,
        pct: Math.round((count / totalApps) * 100),
      })),
      serviceWiseRevenue: Array.from(svcMap.values()).map((s) => ({
        ...s,
        profit: Math.round(s.revenue * 0.7),
      })),
      monthlyCollectionComparison: months.map((m) => ({ label: m, value: monthIncome.get(m) || 0 })),
      staffPerformanceComparison: [],
      outstandingDueAnalysis: [],
      financialYearComparison: [
        { fyCode: fy, income: totalIncomeVal, expense: totalExpVal, netProfit: totalIncomeVal - totalExpVal },
      ],
      top10Services: Array.from(svcMap.values()).sort((a, b) => b.revenue - a.revenue).slice(0, 10),
      top10Customers: [],
      businessGrowthForecast: {
        disclaimer: 'Computed from live historical Firestore collections.',
        points: months.map((m) => ({ label: m, value: monthIncome.get(m) || 0, isEstimate: false })),
      },
    };
    return { data: payload };
  }

  // Builder Schema & Execute
  if (rawPath === '/api/v1/reports/builder/schema' && method === 'GET') {
    return { data: BUILDER_SCHEMAS };
  }
  if (rawPath === '/api/v1/reports/builder/execute' && method === 'POST') {
    const dataset = await executeCustomReportEngine(body as unknown as CustomReportExecutionRequest, actor);
    return { data: dataset };
  }

  // Templates CRUD
  if (rawPath === '/api/v1/reports/templates' && method === 'GET') {
    const list = await safeListCollection('reportTemplates');
    const templates: CustomReportTemplate[] = list.map((t) => ({
      id: Number(t.id || 0),
      templateCode: String(t.templateCode || t.docId || ''),
      name: String(t.name || ''),
      description: String(t.description || ''),
      category: (t.category as ReportDataset['category']) || 'CUSTOM',
      dataSource: (t.dataSource as BuilderDataSourceKey) || 'CUSTOMERS',
      selectedFields: Array.isArray(t.selectedFields) ? (t.selectedFields as string[]) : [],
      filters: Array.isArray(t.filters) ? (t.filters as CustomFilterRule[]) : [],
      filterLogic: t.filterLogic === 'OR' ? 'OR' : 'AND',
      groupByField: String(t.groupByField || ''),
      sortByField: String(t.sortByField || ''),
      sortDirection: t.sortDirection === 'asc' ? 'asc' : 'desc',
      calculatedColumns: Array.isArray(t.calculatedColumns) ? (t.calculatedColumns as CalculatedColumnRule[]) : [],
      includeSubtotals: Boolean(t.includeSubtotals ?? true),
      includeGrandTotal: Boolean(t.includeGrandTotal ?? true),
      roleScope: (t.roleScope as CustomReportTemplate['roleScope']) || 'ALL_PERMITTED',
      versionNo: Number(t.versionNo || 1),
      createdBy: String(t.createdBy || ''),
      updatedAt: String(t.updatedAtIso || toIsoTimestamp(t.updatedAt)),
    }));
    return { data: templates };
  }

  if (rawPath === '/api/v1/reports/templates' && method === 'POST') {
    const templateCode = `TPL-${Date.now().toString(36).toUpperCase()}`;
    const tpl: CustomReportTemplate = {
      id: Date.now(),
      templateCode,
      name: String(body.name || 'Custom Report Template').trim(),
      description: String(body.description || ''),
      category: 'CUSTOM',
      dataSource: (body.dataSource as BuilderDataSourceKey) || 'CUSTOMERS',
      selectedFields: Array.isArray(body.selectedFields) ? (body.selectedFields as string[]) : [],
      filters: Array.isArray(body.filters) ? (body.filters as CustomFilterRule[]) : [],
      filterLogic: body.filterLogic === 'OR' ? 'OR' : 'AND',
      groupByField: String(body.groupByField || ''),
      sortByField: String(body.sortByField || ''),
      sortDirection: body.sortDirection === 'asc' ? 'asc' : 'desc',
      calculatedColumns: Array.isArray(body.calculatedColumns) ? (body.calculatedColumns as CalculatedColumnRule[]) : [],
      includeSubtotals: Boolean(body.includeSubtotals ?? true),
      includeGrandTotal: Boolean(body.includeGrandTotal ?? true),
      roleScope: (body.roleScope as CustomReportTemplate['roleScope']) || 'ALL_PERMITTED',
      versionNo: 1,
      createdBy: actor.userId,
      updatedAt: nowIso,
    };
    await setDoc(doc(firestore, 'reportTemplates', templateCode), {
      ...tpl,
      docId: templateCode,
      updatedAtIso: nowIso,
      createdByUid: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    return { data: tpl, message: 'Custom report template saved to Firestore.' };
  }

  const tplDupMatch = /^\/api\/v1\/reports\/templates\/([^/]+)\/duplicate$/.exec(rawPath);
  if (tplDupMatch && method === 'POST') {
    const origCode = decodeURIComponent(tplDupMatch[1]);
    const snap = await getDoc(doc(firestore, 'reportTemplates', origCode));
    if (!snap.exists()) throw new Error('Template not found.');
    const orig = snap.data() as Record<string, unknown>;
    const nextCode = `TPL-${Date.now().toString(36).toUpperCase()}`;
    const copy = {
      ...orig,
      docId: nextCode,
      templateCode: nextCode,
      name: `${String(orig.name || 'Template')} (Copy)`,
      versionNo: 1,
      createdBy: actor.userId,
      updatedAtIso: nowIso,
      createdByUid: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };
    await setDoc(doc(firestore, 'reportTemplates', nextCode), copy);
    return { data: { ...copy, updatedAt: nowIso } };
  }

  const tplMatch = /^\/api\/v1\/reports\/templates\/([^/]+)$/.exec(rawPath);
  if (tplMatch && method === 'PUT') {
    const code = decodeURIComponent(tplMatch[1]);
    const ref = doc(firestore, 'reportTemplates', code);
    const snap = await getDoc(ref);
    if (!snap.exists()) throw new Error('Template not found.');
    const prev = snap.data() as Record<string, unknown>;
    await updateDoc(ref, {
      ...body,
      versionNo: Number(prev.versionNo || 1) + 1,
      updatedAtIso: nowIso,
      updatedAt: serverTimestamp(),
    });
    return { data: { ...prev, ...body, templateCode: code, updatedAt: nowIso } };
  }
  if (tplMatch && method === 'DELETE') {
    const code = decodeURIComponent(tplMatch[1]);
    await deleteDoc(doc(firestore, 'reportTemplates', code));
    return { data: { deleted: true } };
  }

  // Print Log & Audit Logs
  if (rawPath === '/api/v1/reports/print-log' && method === 'POST') {
    const entry = await recordReportAuditLog({
      actor,
      action: 'PRINT_REPORT',
      reportName: String(body.reportName || 'Report Print'),
      reportCategory: String(body.reportCategory || 'CUSTOM'),
      exportFormat: 'PRINT',
      dateRangeLabel: String(body.dateRangeLabel || 'Current Period'),
      filtersSnapshot: body,
    });
    return { data: entry };
  }

  if (rawPath === '/api/v1/reports/audit-logs' && method === 'GET') {
    const logs = await safeListCollection('reportAuditLogs');
    const actionFilter = (qs.get('action') || '').trim().toUpperCase();
    const search = (qs.get('search') || '').trim().toLowerCase();
    const formatted: ReportAuditLogItem[] = logs
      .map((l) => ({
        id: Number(l.id || 0),
        actorUserId: String(l.actorUserId || ''),
        actorRole: String(l.actorRole || ''),
        action: String(l.action || ''),
        reportName: String(l.reportName || ''),
        reportCategory: String(l.reportCategory || ''),
        filtersSnapshot: (l.filtersSnapshot || {}) as Record<string, unknown>,
        dateRangeLabel: String(l.dateRangeLabel || ''),
        exportFormat: String(l.exportFormat || 'VIEW'),
        status: (l.status as ReportAuditLogItem['status']) || 'SUCCESS',
        ipAddress: String(l.ipAddress || 'Direct-Firebase-TLS'),
        createdAt: String(l.createdAtIso || toIsoTimestamp(l.createdAt)),
      }))
      .filter((l) => {
        if (actionFilter && actionFilter !== 'ALL' && l.action.toUpperCase() !== actionFilter) return false;
        if (search) {
          return `${l.reportName} ${l.actorUserId} ${l.action}`.toLowerCase().includes(search);
        }
        return true;
      })
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return { data: formatted };
  }

  // Archives
  if (rawPath === '/api/v1/reports/archives' && method === 'GET') {
    const list = await safeListCollection('reportArchives');
    const search = (qs.get('search') || '').trim().toLowerCase();
    const fy = (qs.get('financialYear') || '').trim();
    const cat = (qs.get('category') || '').trim();

    const archives: ReportArchiveItem[] = list
      .map((a) => ({
        id: Number(a.id || 0),
        archiveCode: String(a.archiveCode || a.docId || ''),
        reportKey: String(a.reportKey || ''),
        reportTitle: String(a.reportTitle || ''),
        category: (a.category as ReportDataset['category']) || 'CUSTOM',
        financialYear: String(a.financialYear || currentFinancialYear()),
        exportFormat: (a.exportFormat as 'PDF' | 'XLSX' | 'CSV') || 'PDF',
        versionNo: Number(a.versionNo || 1),
        rowCount: Number(a.rowCount || 0),
        checksumSha256: String(a.checksumSha256 || ''),
        fileSizeBytes: Number(a.fileSizeBytes || 0),
        passwordProtected: Boolean(a.passwordProtected),
        retentionDays: Number(a.retentionDays || 365),
        retentionUntil: String(a.retentionUntil || ''),
        deletionStatus: (a.deletionStatus as ReportArchiveItem['deletionStatus']) || 'ACTIVE',
        deletionRequestedBy: (a.deletionRequestedBy as string | null) ?? null,
        deletionReason: (a.deletionReason as string | null) ?? null,
        deletionApprovedBy: (a.deletionApprovedBy as string | null) ?? null,
        generatedBy: String(a.generatedBy || ''),
        generatedRole: String(a.generatedRole || ''),
        createdAt: String(a.createdAtIso || toIsoTimestamp(a.createdAt)),
      }))
      .filter((a) => {
        if (fy && fy !== 'ALL' && a.financialYear !== fy) return false;
        if (cat && cat !== 'ALL' && a.category !== cat) return false;
        if (search) {
          return `${a.archiveCode} ${a.reportTitle} ${a.reportKey}`.toLowerCase().includes(search);
        }
        return true;
      })
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return { data: archives };
  }

  const arcReprintMatch = /^\/api\/v1\/reports\/archives\/([^/]+)\/reprint$/.exec(rawPath);
  if (arcReprintMatch && method === 'POST') {
    const code = decodeURIComponent(arcReprintMatch[1]);
    const entry = await recordReportAuditLog({
      actor,
      action: 'ARCHIVE_REPRINT',
      reportName: code,
      reportCategory: 'ARCHIVE',
      exportFormat: 'PRINT',
    });
    return { data: entry };
  }

  const arcDelReqMatch = /^\/api\/v1\/reports\/archives\/([^/]+)\/delete-request$/.exec(rawPath);
  if (arcDelReqMatch && method === 'POST') {
    const code = decodeURIComponent(arcDelReqMatch[1]);
    const ref = doc(firestore, 'reportArchives', code);
    const snap = await getDoc(ref);
    if (!snap.exists()) throw new Error('Archive record not found.');
    const updates = {
      deletionStatus: 'PENDING_ADMIN_APPROVAL',
      deletionRequestedBy: actor.userId,
      deletionReason: String(body.reason || 'Archive cleanup requested'),
      updatedAt: serverTimestamp(),
    };
    await updateDoc(ref, updates);
    return { data: { ...snap.data(), ...updates } };
  }

  const arcDelRevMatch = /^\/api\/v1\/reports\/archives\/([^/]+)\/delete-review$/.exec(rawPath);
  if (arcDelRevMatch && method === 'POST') {
    if (actor.role !== 'ADMIN') throw new Error('Only Admin can approve archive deletion.');
    const code = decodeURIComponent(arcDelRevMatch[1]);
    const ref = doc(firestore, 'reportArchives', code);
    const snap = await getDoc(ref);
    if (!snap.exists()) throw new Error('Archive record not found.');
    const decision = String(body.decision || 'REJECT');
    const updates = {
      deletionStatus: decision === 'APPROVE' ? 'DELETED' : 'ACTIVE',
      deletionApprovedBy: decision === 'APPROVE' ? actor.userId : null,
      updatedAt: serverTimestamp(),
    };
    await updateDoc(ref, updates);
    return { data: { ...snap.data(), ...updates } };
  }

  // Schedules
  if (rawPath === '/api/v1/reports/schedules' && method === 'GET') {
    const [schedDocs, runDocs] = await Promise.all([
      safeListCollection('reportSchedules'),
      safeListCollection('reportScheduleRuns'),
    ]);
    const schedules: ScheduledReportItem[] = schedDocs.map((s) => ({
      id: Number(s.id || 0),
      scheduleCode: String(s.scheduleCode || s.docId || ''),
      name: String(s.name || ''),
      reportKey: String(s.reportKey || ''),
      templateCode: s.templateCode ? String(s.templateCode) : undefined,
      frequency: (s.frequency as ScheduledReportItem['frequency']) || 'DAILY',
      exportFormat: (s.exportFormat as ScheduledReportItem['exportFormat']) || 'PDF',
      language: s.language === 'bn' ? 'bn' : 'en',
      channels: Array.isArray(s.channels) ? (s.channels as ScheduledReportItem['channels']) : ['INTERNAL'],
      recipients: Array.isArray(s.recipients) ? (s.recipients as string[]) : [],
      runTimeIst: String(s.runTimeIst || '20:00'),
      nextRunAt: String(s.nextRunAt || nowIso),
      lastRunAt: s.lastRunAt ? String(s.lastRunAt) : null,
      lastStatus: (s.lastStatus as ScheduledReportItem['lastStatus']) || 'NEVER_RUN',
      retryLimit: Number(s.retryLimit || 3),
      enabled: Boolean(s.enabled ?? true),
      createdBy: String(s.createdBy || ''),
    }));
    const runs: ScheduleRunItem[] = runDocs
      .map((r) => ({
        id: Number(r.id || 0),
        runCode: String(r.runCode || r.docId || ''),
        scheduleCode: String(r.scheduleCode || ''),
        scheduleName: String(r.scheduleName || ''),
        attemptNo: Number(r.attemptNo || 1),
        status: (r.status as ScheduleRunItem['status']) || 'SUCCESS',
        archiveCodes: Array.isArray(r.archiveCodes) ? (r.archiveCodes as string[]) : [],
        deliveryResults: Array.isArray(r.deliveryResults) ? (r.deliveryResults as ScheduleRunItem['deliveryResults']) : [],
        triggeredBy: String(r.triggeredBy || ''),
        startedAt: String(r.startedAt || nowIso),
        completedAt: String(r.completedAt || nowIso),
      }))
      .sort((a, b) => b.startedAt.localeCompare(a.startedAt));
    return { data: { schedules, runs } };
  }

  if (rawPath === '/api/v1/reports/schedules' && method === 'POST') {
    const scheduleCode = `SCH-${Date.now().toString(36).toUpperCase()}`;
    const sched: ScheduledReportItem = {
      id: Date.now(),
      scheduleCode,
      name: String(body.name || 'Scheduled Report').trim(),
      reportKey: String(body.reportKey || 'CUSTOMER_LIST'),
      frequency: (body.frequency as ScheduledReportItem['frequency']) || 'DAILY',
      exportFormat: (body.exportFormat as ScheduledReportItem['exportFormat']) || 'PDF',
      language: body.language === 'bn' ? 'bn' : 'en',
      channels: Array.isArray(body.channels) ? (body.channels as ScheduledReportItem['channels']) : ['INTERNAL'],
      recipients: Array.isArray(body.recipients) ? (body.recipients as string[]) : [],
      runTimeIst: String(body.runTimeIst || '20:00'),
      nextRunAt: new Date(Date.now() + 86400 * 1000).toISOString(),
      lastRunAt: null,
      lastStatus: 'NEVER_RUN',
      retryLimit: Number(body.retryLimit || 3),
      enabled: Boolean(body.enabled ?? true),
      createdBy: actor.userId,
    };
    await setDoc(doc(firestore, 'reportSchedules', scheduleCode), {
      ...sched,
      docId: scheduleCode,
      createdByUid: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    return { data: sched };
  }

  const schedRunMatch = /^\/api\/v1\/reports\/schedules\/([^/]+)\/run$/.exec(rawPath);
  if (schedRunMatch && method === 'POST') {
    const code = decodeURIComponent(schedRunMatch[1]);
    const schedRef = doc(firestore, 'reportSchedules', code);
    const snap = await getDoc(schedRef);
    if (!snap.exists()) throw new Error('Schedule not found.');
    const schedData = snap.data() as Record<string, unknown>;
    const ds = await buildReportDataset(String(schedData.reportKey || 'CUSTOMER_LIST'), {}, actor);
    const arc = await saveReportArchiveRecord({
      actor,
      reportKey: ds.reportKey,
      reportTitle: ds.title,
      category: ds.category,
      financialYear: ds.financialYear,
      exportFormat: schedData.exportFormat === 'EXCEL' ? 'XLSX' : 'PDF',
      rowCount: ds.rows.length,
      fileSizeBytes: ds.rows.length * 180 + 1024,
    });
    const runCode = `SRUN-${Date.now().toString(36).toUpperCase()}`;
    const runRec: ScheduleRunItem = {
      id: Date.now(),
      runCode,
      scheduleCode: code,
      scheduleName: String(schedData.name || code),
      attemptNo: 1,
      status: 'SUCCESS',
      archiveCodes: [arc.archiveCode],
      deliveryResults: [{ channel: 'INTERNAL', status: 'Delivered', detail: `Archived as ${arc.archiveCode}` }],
      triggeredBy: actor.userId,
      startedAt: nowIso,
      completedAt: new Date().toISOString(),
    };
    await setDoc(doc(firestore, 'reportScheduleRuns', runCode), {
      ...runRec,
      docId: runCode,
      createdByUid: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    await updateDoc(schedRef, {
      lastRunAt: nowIso,
      lastStatus: 'SUCCESS',
      updatedAt: serverTimestamp(),
    });
    return { data: runRec };
  }

  const schedUpdateMatch = /^\/api\/v1\/reports\/schedules\/([^/]+)$/.exec(rawPath);
  if (schedUpdateMatch && method === 'PUT') {
    const code = decodeURIComponent(schedUpdateMatch[1]);
    const schedRef = doc(firestore, 'reportSchedules', code);
    const snap = await getDoc(schedRef);
    if (!snap.exists()) throw new Error('Schedule not found.');
    await updateDoc(schedRef, { ...body, updatedAt: serverTimestamp() });
    return { data: { ...snap.data(), ...body } };
  }

  throw new Error(`Reports route not handled in Firebase mode: ${method} ${rawPath}`);
}
