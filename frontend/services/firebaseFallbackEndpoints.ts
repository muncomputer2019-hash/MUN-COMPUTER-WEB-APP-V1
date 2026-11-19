import { doc, getDoc, serverTimestamp, setDoc, updateDoc } from 'firebase/firestore';
import {
  ApiResponseEnvelope,
  DailyCashClosingRecord,
  ErpApplicationItem,
  ErpCustomerItem,
  ErpExpenseItem,
  ErpPaymentItem,
  ErpRefundItem,
  ErpServiceItem,
  RoleName,
  UserProfile,
} from '../modules/types';
import { OperationType, handleFirestoreError, requireFirebase, timestampToIso } from './firebase';
import { FinanceOverviewPayload } from './financeApi';
import { appendAuditChainEntry } from './clientCryptoAuditService';
import { handleSecurityBackupRoute } from './clientSecurityBackupEngine';
import { handleReportsRoute } from './clientReportsEngine';
import { handleQaRoute } from './clientQaEngine';

export interface FirebaseFallbackContext {
  pathname: string;
  searchParams: URLSearchParams;
  method: string;
  body: Record<string, unknown>;
  uid: string;
  currentProfile: UserProfile;
  isBootAdmin: boolean;
  listShared: (colName: string) => Promise<Record<string, unknown>[]>;
  listScoped: (colName: string) => Promise<Record<string, unknown>[]>;
  allocateSequence: (seqKey: string) => Promise<number>;
  writeSecurityLog: (eventType: string, actorUserId: string, summary: string) => Promise<void>;
  normalizeCustomer: (raw: Record<string, unknown>) => ErpCustomerItem;
  normalizeService: (raw: Record<string, unknown>) => ErpServiceItem;
  normalizeApplication: (raw: Record<string, unknown>) => ErpApplicationItem;
  normalizePayment: (raw: Record<string, unknown>) => ErpPaymentItem;
  normalizeExpense: (raw: Record<string, unknown>) => ErpExpenseItem;
  normalizeRefund: (raw: Record<string, unknown>) => ErpRefundItem;
}

function ok<T>(data: T, message = 'OK'): ApiResponseEnvelope<T> {
  return {
    success: true,
    message,
    data,
    meta: { timestamp: new Date().toISOString() },
  };
}

function failHttp(message: string, status = 400): never {
  const err = new Error(message) as Error & { status?: number };
  err.status = status;
  throw err;
}

function round2(n: number): number {
  return Math.round((n + Number.EPSILON) * 100) / 100;
}

async function saveMasterSettingsSection(
  uid: string,
  sectionKey: string,
  value: unknown,
  message: string
): Promise<void> {
  const { db } = requireFirebase();
  const masterRef = doc(db, 'settings', 'master');
  try {
    const snap = await getDoc(masterRef);
    if (snap.exists()) {
      await updateDoc(masterRef, {
        [sectionKey]: value,
        updatedByUid: uid,
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(masterRef, {
        settingKey: 'master',
        [sectionKey]: value,
        updatedByUid: uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (err) {
    handleFirestoreError(err, OperationType.WRITE, 'settings/master');
  }
  void message;
}

export async function handleExtendedFirebaseEndpoint<T>(
  ctx: FirebaseFallbackContext
): Promise<ApiResponseEnvelope<T> | null> {
  const { pathname, searchParams, method, body, uid, currentProfile, isBootAdmin } = ctx;
  const { db } = requireFirebase();
  const isAdmin = isBootAdmin || currentProfile.role === 'ADMIN';
  const isStaff = currentProfile.role === 'STAFF' || currentProfile.role === 'CUSTOMER';

  // =========================================================================
  // MASTER SETTINGS SAVES & GOVERNANCE COLLECTIONS
  // =========================================================================
  const masterSectionMap: Record<string, string> = {
    '/api/master-settings/global-config': 'globalConfig',
    '/api/master-settings/print-settings': 'printSettings',
    '/api/master-settings/payment-qr': 'paymentQrSettings',
    '/api/master-settings/customer-privacy': 'customerPrivacy',
    '/api/master-settings/security-policy': 'securityPolicy',
    '/api/master-settings/reports': 'reportSettings',
    '/api/master-settings/report-settings': 'reportSettings',
    '/api/master-settings/maintenance': 'maintenanceSettings',
    '/api/master-settings/notifications': 'notificationTemplates',
    '/api/master-settings/document-templates': 'documentTemplates',
    '/api/master-settings/dashboard-preferences': 'dashboardPreferences',
  };

  if (method === 'PUT' && pathname in masterSectionMap) {
    if (!isAdmin) failHttp('Only ADMIN can modify master settings.', 403);
    const key = masterSectionMap[pathname];
    const value =
      key === 'notificationTemplates' && Array.isArray(body.templates)
        ? body.templates
        : key === 'documentTemplates' && Array.isArray(body.templates)
          ? body.templates
          : body;
    await saveMasterSettingsSection(uid, key, value, `Saved ${key}`);
    await ctx.writeSecurityLog('SETTINGS_UPDATED', currentProfile.userId, `Updated ${key} in Firestore settings/master.`);
    return ok(value, `Updated ${key} in Firestore.`) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/daily-cash' && method === 'POST') {
    const seq = await ctx.allocateSequence('CASH');
    const closingCode = `DCC-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${String(seq).padStart(3, '0')}`;
    const openingCash = Number(body.openingCash || 0);
    const cashReceived = Number(body.cashReceived || 0);
    const cashExpenses = Number(body.cashExpenses || 0);
    const expectedCash = round2(openingCash + cashReceived - cashExpenses);
    const actualCashCount = Number(body.actualCashCount ?? expectedCash);
    const cashDifference = round2(actualCashCount - expectedCash);
    const approvalStatus = Math.abs(cashDifference) < 0.01 ? 'Approved' : 'Pending Admin Approval';

    const payload: Record<string, unknown> = {
      id: seq,
      closingCode,
      branchId: 1,
      counterCode: String(body.counterCode || 'CNT-01').slice(0, 40),
      closingDate: String(body.closingDate || new Date().toISOString().slice(0, 10)).slice(0, 32),
      openingCash,
      cashReceived,
      cashExpenses,
      expectedCash,
      actualCashCount,
      cashDifference,
      differenceReason: String(body.differenceReason || '').slice(0, 300),
      submittedBy: currentProfile.userId,
      approvedBy: approvalStatus === 'Approved' ? currentProfile.userId : null,
      approvalStatus,
      correctionAudit: [],
      createdByUid: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };
    try {
      await setDoc(doc(db, 'dailyCashClosings', closingCode), payload);
      const saved = await getDoc(doc(db, 'dailyCashClosings', closingCode));
      const d = saved.data() || payload;
      const record: DailyCashClosingRecord = {
        id: Number(d.id || seq),
        closingCode,
        branchId: 1,
        counterCode: String(d.counterCode || 'CNT-01'),
        closingDate: String(d.closingDate || ''),
        openingCash,
        cashReceived,
        cashExpenses,
        expectedCash,
        actualCashCount,
        cashDifference,
        differenceReason: String(d.differenceReason || ''),
        submittedBy: currentProfile.userId,
        approvedBy: d.approvedBy ? String(d.approvedBy) : null,
        approvalStatus,
        createdAt: timestampToIso(d.createdAt),
        correctionAudit: [],
      };
      return ok(record, `Daily cash closing ${closingCode} recorded.`) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `dailyCashClosings/${closingCode}`);
    }
  }

  const dailyCashApproveMatch = pathname.match(/^\/api\/daily-cash\/([^/]+)\/approve$/);
  if (dailyCashApproveMatch && method === 'POST') {
    if (!isAdmin) failHttp('Only ADMIN can approve daily cash closings.', 403);
    const closingCode = decodeURIComponent(dailyCashApproveMatch[1]);
    const ref = doc(db, 'dailyCashClosings', closingCode);
    try {
      const snap = await getDoc(ref);
      if (!snap.exists()) failHttp('Daily cash closing not found.', 404);
      await updateDoc(ref, {
        approvalStatus: body.decision === 'Rejected' ? 'Rejected' : 'Approved',
        approvedBy: currentProfile.userId,
        updatedAt: serverTimestamp(),
      });
      const updated = await getDoc(ref);
      return ok(updated.data(), 'Daily cash closing updated.') as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `dailyCashClosings/${closingCode}`);
    }
  }

  if (pathname === '/api/master-settings/history' && method === 'GET') {
    const raw = isBootAdmin ? await ctx.listScoped('securityLogs') : [];
    const items = raw
      .filter((r) => String(r.eventType || '').includes('SETTINGS'))
      .map((r, idx) => ({
        id: Number(r.id || idx + 1),
        section: 'Master Settings',
        actorUserId: String(r.actorUserId || currentProfile.userId),
        summary: String(r.summary || ''),
        changedAt: timestampToIso(r.createdAt),
      }));
    return ok(items) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/backups' && method === 'GET') {
    return ok({
      backups: [],
      lastSuccessfulBackup: null,
      nextScheduledBackup: 'Managed by Cloud Firestore automated snapshots & Express encrypted backup engine',
    }) as ApiResponseEnvelope<T>;
  }

  if (
    (pathname === '/api/integrations' ||
      pathname === '/api/documents' ||
      pathname === '/api/settings-proposals' ||
      pathname === '/api/approvals' ||
      pathname === '/api/approval-history' ||
      pathname === '/api/registration-requests' ||
      pathname === '/api/erp/reassignment-requests') &&
    method === 'GET'
  ) {
    return ok([]) as ApiResponseEnvelope<T>;
  }

  if (
    pathname === '/api/audit-logs' ||
    pathname === '/api/security-logs' ||
    pathname === '/api/sessions' ||
    pathname.startsWith('/api/sessions/')
  ) {
    const res = await handleSecurityBackupRoute(
      pathname + (searchParams.toString() ? `?${searchParams.toString()}` : ''),
      method,
      body,
      {
        userId: currentProfile.userId,
        role: currentProfile.role,
        fullName: currentProfile.fullName,
      }
    );
    return ok(res.data, res.message || 'OK') as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/erp/reference-fields' && method === 'GET') {
    return ok([
      { id: 1, fieldKey: 'acknowledgement_number', label: 'Acknowledgement Number', inputType: 'text', uniqueScope: 'GLOBAL', required: false, enabled: true },
      { id: 2, fieldKey: 'application_number', label: 'Portal Application Number', inputType: 'text', uniqueScope: 'PER_SERVICE', required: false, enabled: true },
      { id: 3, fieldKey: 'transaction_id', label: 'Payment Reference / UTR', inputType: 'text', uniqueScope: 'GLOBAL', required: false, enabled: true },
    ]) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/roles' && method === 'GET') {
    const roles = (['ADMIN', 'MANAGER', 'STAFF', 'AUDITOR', 'CUSTOMER'] as RoleName[]).map((role) => ({
      role,
      userCount: currentProfile.role === role ? 1 : 0,
    }));
    return ok(roles) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/permissions' && method === 'GET') {
    return ok({
      modules: ['dashboard', 'customers', 'services', 'applications', 'transactions', 'expenses', 'reports', 'users', 'settings'],
      permissionTypes: ['VIEW', 'ADD', 'EDIT', 'DELETE', 'PRINT', 'EXPORT', 'APPROVE', 'MANAGE'],
      reportPermissions: ['report.view', 'report.create', 'report.export.pdf', 'report.export.excel', 'report.print'],
      matrix: {
        ADMIN: { dashboard: ['VIEW', 'MANAGE'], customers: ['VIEW', 'ADD', 'EDIT', 'DELETE'], applications: ['VIEW', 'ADD', 'EDIT', 'APPROVE'] },
        MANAGER: { dashboard: ['VIEW'], customers: ['VIEW', 'ADD', 'EDIT'], applications: ['VIEW', 'ADD', 'EDIT', 'APPROVE'] },
        STAFF: { dashboard: ['VIEW'], customers: ['VIEW', 'ADD'], applications: ['VIEW', 'ADD', 'EDIT'] },
        EMPLOYEE: { dashboard: ['VIEW'], customers: ['VIEW'], applications: ['VIEW'] },
        AUDITOR: { dashboard: ['VIEW'], customers: ['VIEW'], applications: ['VIEW'] },
        CUSTOMER: { dashboard: ['VIEW'] },
      },
      history: [],
    }) as ApiResponseEnvelope<T>;
  }

  // =========================================================================
  // FINANCE ENGINE OVERVIEW & INVENTORY (COMPUTED FROM LIVE FIRESTORE)
  // =========================================================================
  if (pathname === '/api/finance/overview' && method === 'GET') {
    const [paymentsRaw, expensesRaw, refundsRaw, employeesRaw, payrollRunsRaw] = await Promise.all([
      ctx.listScoped('payments'),
      ctx.listScoped('expenses'),
      ctx.listScoped('refunds'),
      ctx.listShared('employees'),
      ctx.listShared('payrollRuns'),
    ]);
    const payments = paymentsRaw.map(ctx.normalizePayment);
    const expenses = expensesRaw.map(ctx.normalizeExpense);
    const refunds = refundsRaw.map(ctx.normalizeRefund);

    const confirmedCollections = round2(
      payments.filter((p) => p.verificationStatus === 'Confirmed').reduce((s, p) => s + p.amount, 0)
    );
    const cashCollections = round2(
      payments
        .filter((p) => p.verificationStatus === 'Confirmed' && p.paymentMethod === 'Cash')
        .reduce((s, p) => s + p.amount, 0)
    );
    const bankCollections = round2(confirmedCollections - cashCollections);
    const totalRefunds = round2(
      refunds.filter((r) => r.status === 'Processed' || r.status === 'Approved').reduce((s, r) => s + r.refundAmount, 0)
    );
    const netIncome = round2(Math.max(0, confirmedCollections - totalRefunds));
    const totalExpenses = round2(expenses.reduce((s, e) => s + e.amount, 0));
    const netProfit = round2(netIncome - totalExpenses);
    const closingCash = round2(Math.max(0, cashCollections - totalExpenses - totalRefunds));
    const closingBank = round2(Math.max(0, bankCollections));
    const totalCashAndBank = round2(closingCash + closingBank);

    const entityCode = searchParams.get('entityCode') || 'ENT-MAIN';
    const nowIso = new Date().toISOString();

    const coa = [
      { accountCode: '1001', accountName: 'Counter Cash in Hand', accountType: 'Asset', subType: 'Current Asset', normalBalance: 'Debit', entityCode, status: 'active' },
      { accountCode: '1010', accountName: 'Business Bank Account (UPI/NEFT)', accountType: 'Asset', subType: 'Current Asset', normalBalance: 'Debit', entityCode, status: 'active' },
      { accountCode: '3001', accountName: 'Owner Capital & Retained Surplus', accountType: 'Equity', subType: 'Equity', normalBalance: 'Credit', entityCode, status: 'active' },
      { accountCode: '4001', accountName: 'CSC & Digital Service Fee Income', accountType: 'Income', subType: 'Operating Income', normalBalance: 'Credit', entityCode, status: 'active' },
      { accountCode: '6030', accountName: 'Operational & Counter Expenses', accountType: 'Expense', subType: 'Operating Expense', normalBalance: 'Debit', entityCode, status: 'active' },
    ];

    const trialRows = [
      { accountCode: '1001', accountName: 'Counter Cash in Hand', accountType: 'Asset', subType: 'Current Asset', openingDebit: 0, openingCredit: 0, periodDebit: cashCollections, periodCredit: round2(totalExpenses + totalRefunds), closingDebit: closingCash, closingCredit: 0, netBalance: closingCash },
      { accountCode: '1010', accountName: 'Business Bank Account', accountType: 'Asset', subType: 'Current Asset', openingDebit: 0, openingCredit: 0, periodDebit: bankCollections, periodCredit: 0, closingDebit: closingBank, closingCredit: 0, netBalance: closingBank },
      { accountCode: '4001', accountName: 'Service Fee Income', accountType: 'Income', subType: 'Operating Income', openingDebit: 0, openingCredit: 0, periodDebit: totalRefunds, periodCredit: confirmedCollections, closingDebit: 0, closingCredit: netIncome, netBalance: netIncome },
      { accountCode: '6030', accountName: 'Operational Expenses', accountType: 'Expense', subType: 'Operating Expense', openingDebit: 0, openingCredit: 0, periodDebit: totalExpenses, periodCredit: 0, closingDebit: totalExpenses, closingCredit: 0, netBalance: totalExpenses },
    ];
    const sumDebit = round2(closingCash + closingBank + totalExpenses);
    const sumCredit = round2(netIncome);

    const payload: FinanceOverviewPayload = {
      entities: [
        { entityCode: 'ENT-MAIN', entityName: 'MUN COMPUTER — Main Operations', entityType: 'Proprietorship', gstin: '', isActive: true },
        { entityCode: 'ENT-PNB-CSP', entityName: 'PNB CSP Customer Banking (Isolated)', entityType: 'Banking BC', gstin: '', isActive: true },
      ],
      selectedEntity: entityCode,
      statements: {
        entityCode,
        generatedAt: nowIso,
        trialBalance: {
          rows: trialRows,
          totalOpeningDebit: 0,
          totalOpeningCredit: 0,
          totalPeriodDebit: round2(cashCollections + bankCollections + totalExpenses + totalRefunds),
          totalPeriodCredit: round2(confirmedCollections + totalExpenses + totalRefunds),
          totalClosingDebit: sumDebit,
          totalClosingCredit: sumCredit,
          isBalanced: Math.abs(sumDebit - sumCredit) < 0.05,
          difference: round2(sumDebit - sumCredit),
        },
        profitAndLoss: {
          incomeRows: [{ accountCode: '4001', accountName: 'Service Fee Income (Net of Refunds)', amount: netIncome }],
          cogsRows: [],
          expenseRows: [{ accountCode: '6030', accountName: 'Operational Expenses', amount: totalExpenses }],
          totalIncome: netIncome,
          totalCogs: 0,
          grossProfit: netIncome,
          totalExpenses,
          netProfit,
        },
        balanceSheet: {
          assetRows: [
            { accountCode: '1001', accountName: 'Counter Cash in Hand', subType: 'Current Asset', amount: closingCash },
            { accountCode: '1010', accountName: 'Business Bank Account', subType: 'Current Asset', amount: closingBank },
          ],
          liabilityRows: [],
          equityRows: [
            { accountCode: '3999', accountName: 'Current Period Retained Surplus', subType: 'Equity', amount: totalCashAndBank },
          ],
          totalAssets: totalCashAndBank,
          totalLiabilities: 0,
          totalEquityIncludingNetProfit: totalCashAndBank,
          isBalanced: true,
          equationDifference: 0,
        },
        cashFlowStatement: {
          operatingCashFlow: round2(netIncome - totalExpenses),
          investingCashFlow: 0,
          financingCashFlow: 0,
          netCashChange: round2(netIncome - totalExpenses),
          closingCashAndBank: totalCashAndBank,
        },
        costCenterProfitability: [
          { costCenter: 'FRONT_DESK', income: netIncome, directAndOperatingCost: totalExpenses, netContribution: netProfit },
        ],
      },
      kpis: {
        totalAssets: totalCashAndBank,
        totalLiabilities: 0,
        totalEquity: totalCashAndBank,
        totalIncome: netIncome,
        totalCogs: 0,
        grossProfit: netIncome,
        totalExpenses,
        netProfit,
        netMarginPct: netIncome > 0 ? round2((netProfit / netIncome) * 100) : 0,
        closingCashAndBank: totalCashAndBank,
        inventoryValuation: 0,
        supplierPayables: 0,
        customerReceivablesEstimated: 0,
        erpConfirmedRevenue: netIncome,
        pendingApprovalVouchers: 0,
        openFraudAlerts: 0,
        pnbCspIsolated: { deposits: 0, withdrawals: 0, commissionRecognizedToBusiness: 0 },
      },
      fiscalYears: [{ fyCode: 'FY 2026-27', startDate: '2026-04-01', endDate: '2027-03-31', status: 'Open' }],
      fiscalPeriods: [],
      chartOfAccounts: coa,
      vouchers: [],
      cashCounters: [
        { counterCode: 'CNT-01', counterName: 'Counter 01 (Primary Desk)', entityCode: 'ENT-MAIN', custodianUserId: currentProfile.userId, coaAccountCode: '1001', openingBalance: 0, currentBalance: closingCash, isCspCounter: false, status: 'Open' },
      ],
      cashTransfers: [],
      pnbCspLedger: [],
      paymentModes: [
        { modeKey: 'CASH', label: 'Counter Cash', coaAccountCode: '1001', gatewayFeePct: 0, gatewayFixedFee: 0, requiresVerification: false, isGatewayConfigured: true, enabled: true },
        { modeKey: 'UPI', label: 'UPI QR', coaAccountCode: '1010', gatewayFeePct: 0, gatewayFixedFee: 0, requiresVerification: true, isGatewayConfigured: false, enabled: true },
      ],
      customerCredits: [],
      suppliers: [],
      supplierBills: [],
      bankAccounts: [],
      bankStatements: [],
      cheques: [],
      employees: employeesRaw.map((e) => ({
        empId: String(e.empId || e.id || ''),
        fullName: String(e.fullName || ''),
        designation: String(e.designation || ''),
        department: String(e.department || 'Operations'),
        mobile: String(e.mobile || ''),
        basicSalary: Number(e.basicSalary || 0),
        hra: Number(e.hra || 0),
        allowances: Number(e.allowances || 0),
        pfDeduction: Number(e.pfDeduction || 0),
        tdsDeduction: Number(e.tdsDeduction || 0),
        status: String(e.status || 'Active'),
      })),
      payrollRuns: payrollRunsRaw.map((r) => ({
        runId: String(r.runId || r.id || ''),
        monthCode: String(r.monthCode || ''),
        employeeCount: Number(r.employeeCount || 0),
        grossTotal: Number(r.grossTotal ?? r.totalGross ?? 0),
        totalDeductions: Number(r.totalDeductions || 0),
        netPayableTotal: Number(r.netPayableTotal ?? r.totalNet ?? 0),
        voucherNo: String(r.voucherNo || ''),
        slips: Array.isArray(r.slips) ? r.slips : [],
        createdAt: String(r.createdAt || nowIso),
      })),
      taxEntries: [],
      fixedAssets: [],
      budgets: [],
      recurringRules: [],
      products: [],
      inventoryMovements: [],
      loans: [],
      investments: [],
      partners: [],
      franchises: [],
      subscriptions: [],
      currencyRates: [{ currencyCode: 'INR', currencyName: 'Indian Rupee', symbol: '₹', spotRateInr: 1, previousRateInr: 1, updatedAt: nowIso }],
      approvalMatrix: [],
      fraudAlerts: [],
      compliancePolicies: [],
      tasks: [],
      documentVault: [],
      importBatches: [],
      auditObservations: [],
      whiteLabelSettings: { companyName: 'MUN COMPUTER', makerCheckerThresholdInr: 5000 },
      workflowRules: [],
      notificationRules: [],
      latestAuditCertificate: null,
    };
    return ok(payload) as ApiResponseEnvelope<T>;
  }

  // =========================================================================
  // EMPLOYEES & PAYROLL ENGINE (MODULE 09 - DIRECT FIRESTORE)
  // =========================================================================
  if (pathname === '/api/v1/employees' && method === 'GET') {
    const [empRaw, runRaw] = await Promise.all([
      ctx.listShared('employees'),
      ctx.listShared('payrollRuns'),
    ]);
    const employees = empRaw
      .map((e) => ({
        empId: String(e.empId || e.id || ''),
        fullName: String(e.fullName || ''),
        designation: String(e.designation || ''),
        department: String(e.department || 'Operations'),
        mobile: String(e.mobile || ''),
        userId: e.userId ? String(e.userId) : undefined,
        basicSalary: Number(e.basicSalary || 0),
        hra: Number(e.hra || 0),
        allowances: Number(e.allowances || 0),
        pfDeduction: Number(e.pfDeduction || 0),
        tdsDeduction: Number(e.tdsDeduction || 0),
        netSalary: Number(
          e.netSalary ??
            Math.max(
              0,
              Number(e.basicSalary || 0) +
                Number(e.hra || 0) +
                Number(e.allowances || 0) -
                Number(e.pfDeduction || 0) -
                Number(e.tdsDeduction || 0)
            )
        ),
        status: String(e.status || 'Active'),
        createdAt: timestampToIso(e.createdAt),
      }))
      .sort((a, b) => a.empId.localeCompare(b.empId, undefined, { numeric: true }));

    const payrollRuns = runRaw
      .map((r) => ({
        runId: String(r.runId || r.id || ''),
        monthCode: String(r.monthCode || ''),
        voucherNo: String(r.voucherNo || ''),
        employeeCount: Number(r.employeeCount || 0),
        grossTotal: Number(r.grossTotal ?? r.totalGross ?? 0),
        totalDeductions: Number(r.totalDeductions || 0),
        netPayableTotal: Number(r.netPayableTotal ?? r.totalNet ?? 0),
        slips: Array.isArray(r.slips) ? r.slips : [],
        status: String(r.status || 'POSTED'),
        postedBy: String(r.postedBy || ''),
        createdAt: timestampToIso(r.createdAt),
      }))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    return ok({ employees, payrollRuns }) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/v1/employees' && method === 'POST') {
    if (!isAdmin && currentProfile.role !== 'MANAGER') {
      failHttp('Only Admin or Manager can register employees in Payroll Master.', 403);
    }
    const fullName = String(body.fullName || '').trim();
    const designation = String(body.designation || '').trim();
    const department = String(body.department || 'Operations').trim() || 'Operations';
    const mobile = String(body.mobile || '').replace(/\D/g, '').slice(-10);
    const basicSalary = Math.max(0, Number(body.basicSalary || 0));
    const hra = Math.max(0, Number(body.hra || 0));
    const allowances = Math.max(0, Number(body.allowances || 0));
    const pfDeduction = Math.max(0, Number(body.pfDeduction || 0));
    const tdsDeduction = Math.max(0, Number(body.tdsDeduction || 0));

    if (fullName.length < 2) failHttp('Employee full name is required.', 422);
    if (designation.length < 2) failHttp('Designation is required.', 422);
    if (basicSalary <= 0) failHttp('Basic salary must be greater than 0.', 422);

    const existing = await ctx.listShared('employees');
    let nextSeq = await ctx.allocateSequence('EMPLOYEE');
    const maxExistingNum = existing.reduce((m, row) => {
      const match = /^EMP-(\d+)$/i.exec(String(row.empId || ''));
      return match ? Math.max(m, Number(match[1])) : m;
    }, 0);
    if (nextSeq <= maxExistingNum) nextSeq = maxExistingNum + 1;
    const empId = `EMP-${String(nextSeq).padStart(2, '0')}`;
    const netSalary = Math.max(0, round2(basicSalary + hra + allowances - pfDeduction - tdsDeduction));

    const record = {
      empId,
      fullName,
      designation,
      department,
      mobile,
      basicSalary,
      hra,
      allowances,
      pfDeduction,
      tdsDeduction,
      netSalary,
      status: 'Active',
      createdBy: currentProfile.userId,
      createdByUid: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };

    try {
      await setDoc(doc(db, 'employees', empId), record);
      await appendAuditChainEntry({
        userId: currentProfile.userId,
        userRole: currentProfile.role,
        actionType: 'EMPLOYEE_CREATED',
        module: 'Payroll',
        recordId: empId,
        afterValues: { empId, fullName, designation, department, netSalary },
      });
      await ctx.writeSecurityLog(
        'EMPLOYEE_CREATED',
        currentProfile.userId,
        `Added employee ${empId} (${fullName}) to Firestore Payroll Master.`
      );
      return ok(
        {
          ...record,
          createdAt: new Date().toISOString(),
        },
        `Employee ${empId} registered in Payroll Master.`
      ) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `employees/${empId}`);
    }
  }

  if (pathname === '/api/finance/payroll/run' && method === 'POST') {
    if (!isAdmin) {
      failHttp('Only Admin can run and post monthly payroll.', 403);
    }
    const monthCode = String(body.monthCode || new Date().toISOString().slice(0, 7)).trim();
    const empRaw = await ctx.listShared('employees');
    const activeEmps = empRaw.filter((e) => String(e.status || 'Active') === 'Active');
    if (activeEmps.length === 0) {
      failHttp('No active employees found in Payroll Master. Add at least one active employee first.', 422);
    }

    const slips = activeEmps.map((e) => {
      const gross = round2(Number(e.basicSalary || 0) + Number(e.hra || 0) + Number(e.allowances || 0));
      const deductions = round2(Number(e.pfDeduction || 0) + Number(e.tdsDeduction || 0));
      const netPay = Math.max(0, round2(gross - deductions));
      return {
        empId: String(e.empId || ''),
        fullName: String(e.fullName || ''),
        designation: String(e.designation || ''),
        gross,
        deductions,
        netPay,
      };
    });

    const grossTotal = round2(slips.reduce((s, r) => s + r.gross, 0));
    const totalDeductions = round2(slips.reduce((s, r) => s + r.deductions, 0));
    const netPayableTotal = round2(slips.reduce((s, r) => s + r.netPay, 0));

    const runSeq = await ctx.allocateSequence('PAYRUN');
    const runId = `PR-${monthCode.replace(/[^0-9]/g, '')}-${String(runSeq).padStart(3, '0')}`;
    const voucherNo = `JV-PAY-${monthCode.replace(/[^0-9]/g, '')}-${String(runSeq).padStart(3, '0')}`;

    const runPayload = {
      runId,
      monthCode,
      voucherNo,
      employeeCount: slips.length,
      grossTotal,
      totalGross: grossTotal,
      totalDeductions,
      netPayableTotal,
      totalNet: netPayableTotal,
      slips,
      status: 'POSTED',
      postedBy: currentProfile.userId,
      createdByUid: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };

    try {
      await setDoc(doc(db, 'payrollRuns', runId), runPayload);
      await appendAuditChainEntry({
        userId: currentProfile.userId,
        userRole: currentProfile.role,
        actionType: 'PAYROLL_RUN_POSTED',
        module: 'Payroll',
        recordId: runId,
        afterValues: { monthCode, voucherNo, employeeCount: slips.length, netPayableTotal },
      });
      await ctx.writeSecurityLog(
        'PAYROLL_POSTED',
        currentProfile.userId,
        `Posted payroll run ${runId} (${slips.length} staff, net INR ${netPayableTotal}).`
      );
      return ok(
        {
          ...runPayload,
          createdAt: new Date().toISOString(),
        },
        `Payroll ${runId} posted via ${voucherNo}.`
      ) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `payrollRuns/${runId}`);
    }
  }

  if (pathname === '/api/v1/products' && method === 'GET') {
    const raw = await ctx.listShared('products');
    return ok({ products: raw, movements: [] }) as ApiResponseEnvelope<T>;
  }
  if (pathname === '/api/v1/inventory' && method === 'GET') {
    const raw = await ctx.listShared('products');
    return ok({ inventory: raw, movements: [] }) as ApiResponseEnvelope<T>;
  }

  // =========================================================================
  // REPORTS & BI, PHASE 08 SECURITY/BACKUP & PHASE 09 QA (FULL FIRESTORE ENGINE)
  // =========================================================================
  if (pathname.startsWith('/api/v1/reports/')) {
    if (isStaff) failHttp('Reports center requires Manager, Auditor, or Admin permissions.', 403);
    const qs = searchParams.toString();
    const res = await handleReportsRoute(
      pathname + (qs ? `?${qs}` : ''),
      method,
      body,
      {
        userId: currentProfile.userId,
        role: currentProfile.role,
        fullName: currentProfile.fullName,
      }
    );
    return ok(res.data, res.message || 'OK') as ApiResponseEnvelope<T>;
  }

  if (pathname.startsWith('/api/v1/security/')) {
    const qs = searchParams.toString();
    const res = await handleSecurityBackupRoute(
      pathname + (qs ? `?${qs}` : ''),
      method,
      body,
      {
        userId: currentProfile.userId,
        role: currentProfile.role,
        fullName: currentProfile.fullName,
      }
    );
    return ok(res.data, res.message || 'OK') as ApiResponseEnvelope<T>;
  }

  if (pathname.startsWith('/api/v1/qa/')) {
    const qs = searchParams.toString();
    const res = await handleQaRoute(
      pathname + (qs ? `?${qs}` : ''),
      method,
      body,
      {
        userId: currentProfile.userId,
        role: currentProfile.role,
        fullName: currentProfile.fullName,
      }
    );
    return ok(res.data, res.message || 'OK') as ApiResponseEnvelope<T>;
  }

  return null;
}
