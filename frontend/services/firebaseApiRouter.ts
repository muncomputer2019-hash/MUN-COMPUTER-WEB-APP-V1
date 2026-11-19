import {
  Timestamp,
  WriteBatch,
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocs,
  query,
  runTransaction,
  serverTimestamp,
  setDoc,
  updateDoc,
  where,
  writeBatch,
} from 'firebase/firestore';
import {
  ApiResponseEnvelope,
  ConsentCategoryKey,
  CustomerConsentState,
  DailyCashClosingRecord,
  ErpApplicationItem,
  ErpCustomerItem,
  ErpDashboardSummary,
  ErpExpenseItem,
  ErpNotificationDispatchItem,
  ErpPaymentItem,
  ErpRefundItem,
  ErpServiceItem,
  LanguageCode,
  MasterSettingsOverview,
  RoleName,
  ServiceCategoryItem,
  ServiceRateItem,
  ServiceSubcategoryItem,
  ThemeMode,
} from '../modules/types';
import * as OTPAuth from 'otpauth';
import {
  CATALOG_CATEGORIES_21,
  CATALOG_SERVICES_675,
  CATALOG_SUBCATEGORIES,
} from '../../shared/servicesCatalog675';
import {
  normalizeCategoryDoc,
  normalizeServiceDoc,
  normalizeSubcategoryDoc,
} from './servicesRealtime';
import {
  OperationType,
  buildPermissionsForRole,
  ensureFirebaseUserProfile,
  getCurrentUserIdPrefix,
  getFirebaseTotpStatus,
  getIstMonthCode,
  handleFirestoreError,
  requireFirebase,
  resolveFinancialYearCodeIST,
  saveFirebaseTotpConfig,
  timestampToIso,
  verifyFirebaseTotpCode,
} from './firebase';
import { handleCscFirebaseRoute } from './cscFirebaseHandler';
import { handleExtendedFirebaseEndpoint } from './firebaseFallbackEndpoints';

const BOOTSTRAPPED_ADMIN_EMAILS = [
  'muncomputer2019@gmail.com',
  'mamunreja335@gmail.com',
];

function okEnvelope<T>(data: T, message = 'OK'): ApiResponseEnvelope<T> {
  return {
    success: true,
    message,
    data,
    meta: { timestamp: new Date().toISOString() },
  };
}

function failHttp(message: string, status = 400, errors?: Record<string, string[]>): never {
  const err = new Error(message) as Error & {
    status?: number;
    errors?: Record<string, string[]>;
  };
  err.status = status;
  err.errors = errors;
  throw err;
}

function parseBody(body?: BodyInit | null): Record<string, unknown> {
  if (!body || typeof body !== 'string') return {};
  try {
    return JSON.parse(body) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function str(val: unknown, maxLen: number): string {
  return String(val ?? '').trim().slice(0, maxLen);
}

function isBootstrappedAdminEmail(email?: string | null, verified?: boolean): boolean {
  return Boolean(
    verified && email && BOOTSTRAPPED_ADMIN_EMAILS.includes(email.toLowerCase())
  );
}

async function allocateSequence(seqKey: string): Promise<number> {
  const { auth, db } = requireFirebase();
  const uid = auth.currentUser?.uid;
  if (!uid) failHttp('Authentication required.', 401);

  const seqRef = doc(db, 'sequences', seqKey);
  try {
    return await runTransaction(db, async (tx) => {
      const snap = await tx.get(seqRef);
      if (!snap.exists()) {
        tx.set(seqRef, {
          seqKey,
          currentValue: 1,
          updatedByUid: uid,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
        return 1;
      }
      const next = Number(snap.data().currentValue || 0) + 1;
      tx.update(seqRef, {
        currentValue: next,
        updatedByUid: uid,
        updatedAt: serverTimestamp(),
      });
      return next;
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.WRITE, `sequences/${seqKey}`);
  }
}

async function writeSecurityLog(eventType: string, actorUserId: string, summary: string) {
  const { auth, db } = requireFirebase();
  const uid = auth.currentUser?.uid;
  if (!uid) return;
  const logId = `LOG-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
  try {
    await setDoc(doc(db, 'securityLogs', logId), {
      id: Date.now(),
      eventType: str(eventType, 64),
      actorUserId: str(actorUserId, 64),
      result: 'SUCCESS',
      ipAddress: 'Firebase Client',
      deviceInfo: typeof navigator !== 'undefined' ? navigator.userAgent.slice(0, 120) : 'Web Client',
      summary: str(summary, 400),
      createdByUid: uid,
      createdAt: serverTimestamp(),
    });
  } catch {
    // Audit write should not crash primary business flow if log-only
  }
}

function normalizeCustomerDoc(raw: Record<string, unknown>): ErpCustomerItem {
  return {
    id: Number(raw.id || 1),
    customerId: String(raw.customerId || ''),
    fullName: String(raw.fullName || ''),
    fatherOrHusbandName: String(raw.fatherOrHusbandName || ''),
    dob: String(raw.dob || ''),
    gender: (raw.gender as ErpCustomerItem['gender']) || 'Male',
    mobile: String(raw.mobile || ''),
    whatsapp: String(raw.whatsapp || ''),
    email: String(raw.email || ''),
    aadhaarMasked: raw.aadhaarMasked ? String(raw.aadhaarMasked) : undefined,
    panNumber: raw.panNumber ? String(raw.panNumber) : undefined,
    voterId: raw.voterId ? String(raw.voterId) : undefined,
    village: String(raw.village || ''),
    postOffice: String(raw.postOffice || ''),
    policeStation: String(raw.policeStation || ''),
    district: String(raw.district || ''),
    pinCode: String(raw.pinCode || ''),
    presentAddress: String(raw.presentAddress || ''),
    permanentAddress: String(raw.permanentAddress || ''),
    sameAsPresent: Boolean(raw.sameAsPresent ?? true),
    segment: (raw.segment as ErpCustomerItem['segment']) || 'Individual',
    crmTag: String(raw.crmTag || 'Standard'),
    status: (raw.status as ErpCustomerItem['status']) || 'Active',
    verificationStatus: String(raw.verificationStatus || 'Unverified'),
    mobileOtpVerifiedAt: raw.mobileOtpVerifiedAt ? String(raw.mobileOtpVerifiedAt) : null,
    consents: Array.isArray(raw.consents) ? (raw.consents as ErpCustomerItem['consents']) : [],
    consentHistory: Array.isArray(raw.consentHistory)
      ? (raw.consentHistory as ErpCustomerItem['consentHistory'])
      : [],
    contactHistory: Array.isArray(raw.contactHistory)
      ? (raw.contactHistory as ErpCustomerItem['contactHistory'])
      : [],
    notesAndFollowUps: Array.isArray(raw.notesAndFollowUps)
      ? (raw.notesAndFollowUps as ErpCustomerItem['notesAndFollowUps'])
      : [],
    deletedAt: raw.deletedAt ? String(raw.deletedAt) : null,
    createdAt: timestampToIso(raw.createdAt),
  };
}

// normalizeServiceDoc is imported from ./servicesRealtime for single-source consistency

function normalizeApplicationDoc(raw: Record<string, unknown>): ErpApplicationItem {
  return {
    id: Number(raw.id || 1),
    applicationNo: String(raw.applicationNo || ''),
    financialYear: String(raw.financialYear || '2026-27'),
    customerId: String(raw.customerId || ''),
    customerSnapshot: (raw.customerSnapshot as ErpApplicationItem['customerSnapshot']) || {
      customerId: String(raw.customerId || ''),
      fullName: '',
      fatherOrHusbandName: '',
      dob: '',
      gender: 'Male',
      mobile: '',
      whatsapp: '',
      village: '',
      presentAddress: '',
    },
    serviceId: String(raw.serviceId || ''),
    serviceSnapshot: (raw.serviceSnapshot as ErpApplicationItem['serviceSnapshot']) || {
      serviceId: String(raw.serviceId || ''),
      serviceCode: '',
      name: '',
      categoryName: '',
      appliedFormVersion: 1,
      formFieldsSnapshot: [],
      requiredDocsSnapshot: [],
      customerChargeSnapshot: 0,
      serviceCostSnapshot: 0,
      profitSnapshot: 0,
      termsSnapshot: '',
    },
    formData: (raw.formData as Record<string, unknown>) || {},
    status: (raw.status as ErpApplicationItem['status']) || 'Submitted',
    assignedStaffId: raw.assignedStaffId ? String(raw.assignedStaffId) : null,
    assignedCounterCode: raw.assignedCounterCode ? String(raw.assignedCounterCode) : null,
    submissionDate: raw.submissionDate ? String(raw.submissionDate) : null,
    expectedCompletionDate: String(raw.expectedCompletionDate || ''),
    actualCompletionDate: raw.actualCompletionDate ? String(raw.actualCompletionDate) : null,
    mandatoryDocExceptionReason: raw.mandatoryDocExceptionReason
      ? String(raw.mandatoryDocExceptionReason)
      : null,
    duplicateOverrideReason: raw.duplicateOverrideReason
      ? String(raw.duplicateOverrideReason)
      : null,
    references: Array.isArray(raw.references)
      ? (raw.references as ErpApplicationItem['references'])
      : [],
    statusHistory: Array.isArray(raw.statusHistory)
      ? (raw.statusHistory as ErpApplicationItem['statusHistory'])
      : [],
    assignmentHistory: Array.isArray(raw.assignmentHistory)
      ? (raw.assignmentHistory as ErpApplicationItem['assignmentHistory'])
      : [],
    checklistSummary: (raw.checklistSummary as ErpApplicationItem['checklistSummary']) || {
      requiredDocuments: 0,
      optionalDocuments: 0,
      uploadedDocuments: 0,
      uploadedMandatoryCount: 0,
      verifiedDocuments: 0,
      pendingVerification: 0,
      rejectedDocuments: 0,
      missingCount: 0,
      missingRequiredLabels: [],
      isSubmissionReady: true,
    },
    slaStatus: (raw.slaStatus as ErpApplicationItem['slaStatus']) || {
      label: 'On Track',
      badge: 'success',
    },
    documents: Array.isArray(raw.documents)
      ? (raw.documents as ErpApplicationItem['documents'])
      : [],
    financialSummary: (raw.financialSummary as ErpApplicationItem['financialSummary']) || {
      serviceCharge: 0,
      serviceCost: 0,
      profitAmount: 0,
      totalPaid: 0,
      totalRefunded: 0,
      netCollected: 0,
      balanceDue: 0,
      paymentStatus: 'Unpaid',
    },
    payments: Array.isArray(raw.payments) ? (raw.payments as ErpApplicationItem['payments']) : [],
    refunds: Array.isArray(raw.refunds) ? (raw.refunds as ErpApplicationItem['refunds']) : [],
    followUps: Array.isArray(raw.followUps) ? (raw.followUps as ErpApplicationItem['followUps']) : [],
    notes: Array.isArray(raw.notes) ? (raw.notes as ErpApplicationItem['notes']) : [],
    delivery: (raw.delivery as ErpApplicationItem['delivery']) || null,
    cancellations: Array.isArray(raw.cancellations)
      ? (raw.cancellations as ErpApplicationItem['cancellations'])
      : [],
    reassignments: Array.isArray(raw.reassignments)
      ? (raw.reassignments as ErpApplicationItem['reassignments'])
      : [],
    notifications: Array.isArray(raw.notifications)
      ? (raw.notifications as ErpApplicationItem['notifications'])
      : [],
    activities: Array.isArray(raw.activities)
      ? (raw.activities as ErpApplicationItem['activities'])
      : [],
    archivedAt: raw.archivedAt ? String(raw.archivedAt) : null,
    createdBy: String(raw.createdBy || ''),
    createdAt: timestampToIso(raw.createdAt),
    updatedAt: timestampToIso(raw.updatedAt),
  };
}

function normalizePaymentDoc(raw: Record<string, unknown>): ErpPaymentItem {
  return {
    id: Number(raw.id || 1),
    transactionId: String(raw.transactionId || ''),
    receiptNo: String(raw.receiptNo || ''),
    invoiceNo: raw.invoiceNo ? String(raw.invoiceNo) : undefined,
    applicationNo: String(raw.applicationNo || ''),
    customerId: String(raw.customerId || ''),
    customerName: String(raw.customerName || ''),
    serviceId: String(raw.serviceId || ''),
    serviceName: String(raw.serviceName || ''),
    counterCode: String(raw.counterCode || 'CNT-01'),
    collectedBy: String(raw.collectedBy || ''),
    paymentType: (raw.paymentType as ErpPaymentItem['paymentType']) || 'Full',
    paymentMethod: (raw.paymentMethod as ErpPaymentItem['paymentMethod']) || 'Cash',
    upiReference: raw.upiReference ? String(raw.upiReference) : undefined,
    amount: Number(raw.amount || 0),
    verificationStatus:
      (raw.verificationStatus as ErpPaymentItem['verificationStatus']) || 'Confirmed',
    verifiedBy: raw.verifiedBy ? String(raw.verifiedBy) : null,
    recordedAt: timestampToIso(raw.recordedAt || raw.createdAt),
    notes: String(raw.notes || ''),
  };
}

function normalizeExpenseDoc(raw: Record<string, unknown>): ErpExpenseItem {
  return {
    id: Number(raw.id || 1),
    voucherNo: String(raw.voucherNo || ''),
    category: String(raw.category || ''),
    description: String(raw.description || ''),
    counterCode: String(raw.counterCode || 'CNT-01'),
    amount: Number(raw.amount || 0),
    expenseDate: String(raw.expenseDate || new Date().toISOString().slice(0, 10)),
    recordedBy: String(raw.recordedBy || ''),
    status: (raw.status as ErpExpenseItem['status']) || 'Approved',
    createdAt: timestampToIso(raw.createdAt),
  };
}

function normalizeRefundDoc(raw: Record<string, unknown>): ErpRefundItem {
  return {
    id: Number(raw.id || 1),
    refundId: String(raw.refundId || ''),
    applicationNo: String(raw.applicationNo || ''),
    customerId: String(raw.customerId || ''),
    originalTransactionId: String(raw.originalTransactionId || ''),
    refundType: (raw.refundType as ErpRefundItem['refundType']) || 'Partial',
    refundAmount: Number(raw.refundAmount || 0),
    refundMethod: (raw.refundMethod as ErpRefundItem['refundMethod']) || 'Cash',
    refundReason: String(raw.refundReason || ''),
    status: (raw.status as ErpRefundItem['status']) || 'Pending',
    requestedBy: String(raw.requestedBy || ''),
    approvedBy: raw.approvedBy ? String(raw.approvedBy) : null,
    processedBy: raw.processedBy ? String(raw.processedBy) : null,
    createdAt: timestampToIso(raw.createdAt),
    processedAt: raw.processedAt ? String(raw.processedAt) : null,
  };
}

const SHARED_READ_COLLECTIONS = new Set([
  'customers',
  'serviceCategories',
  'serviceSubcategories',
  'services',
  'departments',
]);

async function listCollectionScoped(collectionName: string): Promise<Record<string, unknown>[]> {
  const { auth, db } = requireFirebase();
  const fbUser = auth.currentUser;
  if (!fbUser) failHttp('Authentication required.', 401);

  const isBootAdmin = isBootstrappedAdminEmail(fbUser.email, fbUser.emailVerified);
  const colRef = collection(db, collectionName);
  const q =
    isBootAdmin || SHARED_READ_COLLECTIONS.has(collectionName)
      ? query(colRef)
      : query(colRef, where('createdByUid', '==', fbUser.uid));

  try {
    const snap = await getDocs(q);
    return snap.docs.map((d) => d.data() as Record<string, unknown>);
  } catch (err) {
    handleFirestoreError(err, OperationType.LIST, collectionName);
  }
}

const LEGACY_MOCK_CATEGORY_IDS = ['CAT-ONLINE', 'CAT-CITIZEN', 'CAT-TECH'];
const LEGACY_MOCK_SERVICE_IDS = ['SRV-101', 'SRV-102', 'SRV-103'];

async function commitBatchedWrites(
  ops: Array<(batch: WriteBatch) => void>
): Promise<void> {
  const { db } = requireFirebase();
  const CHUNK_SIZE = 400;
  for (let i = 0; i < ops.length; i += CHUNK_SIZE) {
    const chunk = ops.slice(i, i + CHUNK_SIZE);
    const batch = writeBatch(db);
    for (const applyOp of chunk) {
      applyOp(batch);
    }
    await batch.commit();
  }
}

async function ensureSequenceAtLeast(seqKey: string, minValue: number, uid: string): Promise<void> {
  const { db } = requireFirebase();
  const seqRef = doc(db, 'sequences', seqKey);
  const snap = await getDoc(seqRef);
  if (!snap.exists()) {
    await setDoc(seqRef, {
      seqKey,
      currentValue: minValue,
      updatedByUid: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
  } else {
    const cur = Number(snap.data().currentValue || 0);
    if (cur < minValue) {
      await updateDoc(seqRef, {
        currentValue: minValue,
        updatedByUid: uid,
        updatedAt: serverTimestamp(),
      });
    }
  }
}

interface CatalogSyncResult {
  categoriesCount: number;
  subcategoriesCount: number;
  servicesCount: number;
  codeRange: string;
  legacyRemovedCount: number;
}

let inFlightCatalogSync: Promise<CatalogSyncResult> | null = null;

async function syncCatalog675ToFirestore(
  uid: string,
  actorUserId: string
): Promise<CatalogSyncResult> {
  if (inFlightCatalogSync) return inFlightCatalogSync;

  inFlightCatalogSync = (async () => {
    const { db } = requireFirebase();
    const nowIso = new Date().toISOString();
    try {
      const [catsSnap, subsSnap, svcsSnap, seedSettingSnap] = await Promise.all([
        getDocs(collection(db, 'serviceCategories')),
        getDocs(collection(db, 'serviceSubcategories')),
        getDocs(collection(db, 'services')),
        getDoc(doc(db, 'settings', 'catalogSeed')),
      ]);

      const existingCats = new Map<string, Record<string, unknown>>();
      catsSnap.docs.forEach((d) => existingCats.set(d.id, d.data() as Record<string, unknown>));

      const existingSubs = new Map<string, Record<string, unknown>>();
      subsSnap.docs.forEach((d) => existingSubs.set(d.id, d.data() as Record<string, unknown>));

      const existingSvcs = new Map<string, Record<string, unknown>>();
      svcsSnap.docs.forEach((d) => existingSvcs.set(d.id, d.data() as Record<string, unknown>));

      const ops: Array<(batch: WriteBatch) => void> = [];
      let legacyRemovedCount = 0;

      for (const oldCatId of LEGACY_MOCK_CATEGORY_IDS) {
        if (existingCats.has(oldCatId)) {
          ops.push((b) => b.delete(doc(db, 'serviceCategories', oldCatId)));
          legacyRemovedCount += 1;
        }
      }
      for (const oldSrvId of LEGACY_MOCK_SERVICE_IDS) {
        if (existingSvcs.has(oldSrvId)) {
          ops.push((b) => b.delete(doc(db, 'services', oldSrvId)));
          legacyRemovedCount += 1;
        }
      }

      for (const cat of CATALOG_CATEGORIES_21) {
        const ref = doc(db, 'serviceCategories', cat.code);
        const prev = existingCats.get(cat.code);
        if (prev) {
          ops.push((b) =>
            b.update(ref, {
              id: cat.id,
              code: cat.code,
              name: cat.name,
              description: cat.description.slice(0, 400),
              displayOrder: cat.displayOrder,
              status: prev.status || 'active',
              updatedBy: actorUserId,
              updatedAt: serverTimestamp(),
            })
          );
        } else {
          ops.push((b) =>
            b.set(ref, {
              id: cat.id,
              code: cat.code,
              name: cat.name,
              description: cat.description.slice(0, 400),
              displayOrder: cat.displayOrder,
              status: 'active',
              proposedBy: actorUserId,
              approvedBy: actorUserId,
              createdBy: actorUserId,
              updatedBy: actorUserId,
              createdByUid: uid,
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp(),
            })
          );
        }
      }

      for (const sub of CATALOG_SUBCATEGORIES) {
        const ref = doc(db, 'serviceSubcategories', sub.code);
        const prev = existingSubs.get(sub.code);
        if (prev) {
          ops.push((b) =>
            b.update(ref, {
              id: sub.id,
              code: sub.code,
              categoryId: sub.categoryId,
              categoryName: sub.categoryName,
              name: sub.name,
              description: sub.description.slice(0, 400),
              displayOrder: sub.displayOrder,
              status: prev.status || 'active',
              updatedBy: actorUserId,
              updatedAt: serverTimestamp(),
            })
          );
        } else {
          ops.push((b) =>
            b.set(ref, {
              id: sub.id,
              code: sub.code,
              categoryId: sub.categoryId,
              categoryName: sub.categoryName,
              name: sub.name,
              description: sub.description.slice(0, 400),
              displayOrder: sub.displayOrder,
              status: 'active',
              createdBy: actorUserId,
              updatedBy: actorUserId,
              createdByUid: uid,
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp(),
            })
          );
        }
      }

      for (const def of CATALOG_SERVICES_675) {
        const ref = doc(db, 'services', def.serviceId);
        const prev = existingSvcs.get(def.serviceId);
        if (prev) {
          ops.push((b) =>
            b.update(ref, {
              id: def.id,
              name: def.name.slice(0, 160),
              categoryId: def.categoryId,
              categoryName: def.categoryName.slice(0, 120),
              subcategoryId: def.subcategoryId,
              subcategoryName: def.subcategoryName.slice(0, 120),
              description: (typeof prev.description === 'string' && prev.description) || def.description.slice(0, 600),
              displayOrder: prev.displayOrder !== undefined ? Number(prev.displayOrder) : def.displayOrder,
              updatedBy: actorUserId,
              updatedAt: serverTimestamp(),
            })
          );
        } else {
          const instructions = def.serviceInstructions.slice(0, 2000);
          ops.push((b) =>
            b.set(ref, {
              id: def.id,
              serviceId: def.serviceId,
              serviceCode: def.serviceCode,
              name: def.name.slice(0, 160),
              categoryId: def.categoryId,
              categoryName: def.categoryName.slice(0, 120),
              subcategoryId: def.subcategoryId,
              subcategoryName: def.subcategoryName.slice(0, 120),
              description: def.description.slice(0, 600),
              serviceCharge: 0,
              serviceCost: 0,
              govtFee: 0,
              additionalCharges: 0,
              totalCustomerCharge: 0,
              customerCharge: 0,
              profitAmount: 0,
              status: 'Active',
              availability: 'Available',
              serviceInstructions: instructions,
              termsAndConditions: instructions,
              displayOrder: def.displayOrder,
              sla: {
                processingMode: 'FIXED',
                expectedDays: def.expectedDays,
                minDays: 1,
                maxDays: Math.max(def.expectedDays + 2, 3),
                dayType: 'WORKING',
                excludeHolidays: true,
                startEvent: 'ON_SUBMIT',
                pauseOnStatuses: ['Pending Customer', 'Pending Office', 'On Hold'],
                warningThresholdPct: 75,
                breachThresholdHours: 72,
              },
              requiredDocuments: def.requiredDocuments.map((d) => ({
                docKey: d.docKey,
                label: d.label,
                category: d.category,
                required: d.required,
                allowMultiple: false,
                allowedFormats: ['PDF', 'JPG', 'JPEG', 'PNG'],
                maxSizeMb: 10,
                instructions: 'Valid government identity proof.',
                enabled: true,
              })),
              currentFormVersion: 1,
              formVersions: [
                {
                  versionNo: 1,
                  publishedAt: nowIso,
                  publishedBy: actorUserId,
                  status: 'published',
                  fields: [
                    {
                      fieldKey: 'applicant_name',
                      label: 'Applicant Full Name',
                      fieldType: 'short_text',
                      required: true,
                      displayOrder: 1,
                      enabled: true,
                    },
                    {
                      fieldKey: 'applicant_mobile',
                      label: 'Mobile Number',
                      fieldType: 'mobile',
                      required: true,
                      displayOrder: 2,
                      enabled: true,
                    },
                    {
                      fieldKey: 'service_notes',
                      label: 'Service Request Notes / Details',
                      fieldType: 'long_text',
                      required: false,
                      displayOrder: 3,
                      enabled: true,
                    },
                  ],
                },
              ],
              automationRules: [],
              processingTimeHistory: [],
              deletedAt: null,
              createdBy: actorUserId,
              updatedBy: actorUserId,
              createdByUid: uid,
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp(),
            })
          );
        }
      }

      await commitBatchedWrites(ops);

      const fyCode = resolveFinancialYearCodeIST();
      await Promise.all([
        ensureSequenceAtLeast('CAT', CATALOG_CATEGORIES_21.length, uid),
        ensureSequenceAtLeast('SUB', CATALOG_SUBCATEGORIES.length, uid),
        ensureSequenceAtLeast(`MCS_${fyCode}`, CATALOG_SERVICES_675.length, uid),
        ensureSequenceAtLeast(`SRV_${fyCode}`, CATALOG_SERVICES_675.length, uid),
      ]);

      const seedRef = doc(db, 'settings', 'catalogSeed');
      const metaPayload = {
        seeded675: true,
        categoriesCount: CATALOG_CATEGORIES_21.length,
        subcategoriesCount: CATALOG_SUBCATEGORIES.length,
        servicesCount: CATALOG_SERVICES_675.length,
        codeRange: `${CATALOG_SERVICES_675[0]?.serviceCode ?? 'MC2627SRV-001'} to ${
          CATALOG_SERVICES_675[CATALOG_SERVICES_675.length - 1]?.serviceCode ?? 'MC2627SRV-675'
        }`,
        seededBy: actorUserId,
        seededAt: nowIso,
      };
      if (seedSettingSnap.exists()) {
        await updateDoc(seedRef, {
          catalogSeedMeta: metaPayload,
          updatedByUid: uid,
          updatedAt: serverTimestamp(),
        });
      } else {
        await setDoc(seedRef, {
          settingKey: 'catalogSeed',
          catalogSeedMeta: metaPayload,
          updatedByUid: uid,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
      }

      return {
        categoriesCount: CATALOG_CATEGORIES_21.length,
        subcategoriesCount: CATALOG_SUBCATEGORIES.length,
        servicesCount: CATALOG_SERVICES_675.length,
        codeRange: metaPayload.codeRange,
        legacyRemovedCount,
      };
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, 'services');
    } finally {
      inFlightCatalogSync = null;
    }
  })();

  return inFlightCatalogSync;
}

async function ensureCatalogSeededIfEmpty(uid: string, actorUserId: string): Promise<void> {
  const { db } = requireFirebase();
  try {
    const [svcsSnap, seedSettingSnap] = await Promise.all([
      getDocs(collection(db, 'services')),
      getDoc(doc(db, 'settings', 'catalogSeed')),
    ]);

    const onlyLegacyMock =
      svcsSnap.docs.length > 0 &&
      svcsSnap.docs.every((d) => LEGACY_MOCK_SERVICE_IDS.includes(d.id));

    const alreadySeeded675 = Boolean(seedSettingSnap.exists() && seedSettingSnap.data()?.catalogSeedMeta?.seeded675);

    if ((svcsSnap.empty && !alreadySeeded675) || onlyLegacyMock) {
      await syncCatalog675ToFirestore(uid, actorUserId);
    }
  } catch (err) {
    console.warn('675 catalog auto-seed check skipped:', err);
  }
}

export async function handleFirebaseApiRequest<T>(
  rawPath: string,
  options: RequestInit = {}
): Promise<ApiResponseEnvelope<T>> {
  const { auth, db } = requireFirebase();
  const [pathname, queryStr = ''] = rawPath.split('?');
  const searchParams = new URLSearchParams(queryStr);
  const method = (options.method || 'GET').toUpperCase();
  const body = parseBody(options.body);

  const fbUser = auth.currentUser;
  if (!fbUser) {
    failHttp('Authentication required. Please sign in with Firebase.', 401);
  }
  const { user: currentProfile } = await ensureFirebaseUserProfile(fbUser);
  const uid = fbUser.uid;
  const isBootAdmin = isBootstrappedAdminEmail(fbUser.email, fbUser.emailVerified);

  if (pathname.startsWith('/api/csc/')) {
    const cscHandled = await handleCscFirebaseRoute<T>(
      pathname,
      method,
      searchParams,
      body,
      uid,
      currentProfile,
      isBootAdmin
    );
    if (cscHandled) return cscHandled;
  }

  // =========================================================================
  // AUTH / SESSION
  // =========================================================================
  if (pathname === '/api/auth/me' && method === 'GET') {
    return okEnvelope({
      user: currentProfile,
      permissions: buildPermissionsForRole(currentProfile.role),
      csrfToken: null,
      session: {
        id: uid,
        expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
      },
    }) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/auth/totp/status' && method === 'GET') {
    const status = await getFirebaseTotpStatus(uid);
    return okEnvelope({
      totpEnabled: status.totpEnabled,
      userId: currentProfile.userId,
    }) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/auth/totp/enable' && method === 'POST') {
    const secret = str(body.secret, 128).toUpperCase().replace(/\s+/g, '');
    const code = str(body.code, 12);
    if (!secret || !/^\d{6}$/.test(code)) {
      failHttp('Valid Base32 setup key and 6-digit Google Authenticator code are required.', 422);
    }
    try {
      const totp = new OTPAuth.TOTP({
        issuer: 'MUN COMPUTER',
        label: currentProfile.email || currentProfile.userId,
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(secret),
      });
      if (totp.validate({ token: code, window: 1 }) === null) {
        failHttp('Invalid 6-digit Google Authenticator verification code.', 422);
      }
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      failHttp('Invalid Base32 TOTP setup key.', 422);
    }

    await saveFirebaseTotpConfig(secret, true);
    await writeSecurityLog(
      'PROFILE_UPDATED',
      currentProfile.userId,
      `Google Authenticator (TOTP 2FA) enabled in Firestore for ${currentProfile.userId}.`
    );
    return okEnvelope({ totpEnabled: true }, 'Google Authenticator enabled in Firestore.') as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/auth/totp/verify-code' && method === 'POST') {
    const code = str(body.code, 12);
    if (!/^\d{6}$/.test(code)) {
      failHttp('Enter a valid 6-digit Google Authenticator code.', 422);
    }
    const status = await getFirebaseTotpStatus(uid);
    if (!status.totpEnabled) {
      failHttp('Google Authenticator is not yet linked to your account.', 400);
    }
    const valid = await verifyFirebaseTotpCode(code, uid);
    if (!valid) {
      failHttp('Invalid 6-digit Google Authenticator code.', 401);
    }
    await writeSecurityLog(
      'LOGIN_SUCCESS',
      currentProfile.userId,
      `Google Authenticator (TOTP) 6-digit code verified for ${currentProfile.userId}.`
    );
    return okEnvelope({ verified: true }, 'Google Authenticator code verified.') as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/auth/totp/disable' && method === 'POST') {
    await saveFirebaseTotpConfig('', false);
    await writeSecurityLog(
      'PROFILE_UPDATED',
      currentProfile.userId,
      `Google Authenticator (TOTP 2FA) disabled in Firestore for ${currentProfile.userId}.`
    );
    return okEnvelope({ totpEnabled: false }, 'Google Authenticator disabled.') as ApiResponseEnvelope<T>;
  }

  // =========================================================================
  // MASTER SETTINGS & PREFERENCES
  // =========================================================================
  if (pathname === '/api/master-settings/overview' && method === 'GET') {
    let masterData: Record<string, unknown> = {};
    let prefData: Record<string, unknown> = {};
    try {
      const mSnap = await getDoc(doc(db, 'settings', 'master'));
      if (mSnap.exists()) masterData = mSnap.data();
    } catch {
      // Initial master doc not created yet
    }
    try {
      const pSnap = await getDoc(doc(db, 'settings', `pref_${uid}`));
      if (pSnap.exists()) prefData = pSnap.data();
    } catch {
      // Initial pref doc not created yet
    }

    const defaultOverview: MasterSettingsOverview = {
      companyProfile: (masterData.companyProfile as MasterSettingsOverview['companyProfile']) || {
        companyName: 'MUN COMPUTER',
        addressLine: 'Village Mamudpur (Chowmatha More)',
        postOffice: 'Juginda',
        policeStation: 'Domkal',
        district: 'Murshidabad',
        stateName: 'West Bengal',
        countryName: 'India',
        pinCode: '742406',
        mobile: '+91 8101352105',
        whatsapp: '+91 8101352105',
        email: 'MUNCOMPUTER2019@GMAIL.COM',
        website: '',
        gstNumber: '',
        panNumber: '',
        upiId: '',
        bankDetails: '',
        logoUrl: '/assets/aistudio/MUN_Computer_Orbit_Logo_11zon_1fce5a24.jpg',
        signatureUrl: '',
        stampUrl: '',
        updatedAt: timestampToIso(masterData.updatedAt),
      },
      globalConfig: (masterData.globalConfig as MasterSettingsOverview['globalConfig']) || {
        financialYearLabel: '2026-27',
        financialYearStartMonth: 4,
        financialYearEndMonth: 3,
        timezone: 'Asia/Kolkata',
        defaultLanguage: 'en',
        dateFormat: 'DD/MM/YYYY',
        currencyCode: 'INR',
        currencySymbol: '₹',
        prefixes: { RECEIPT: 'REC', INVOICE: 'INV', APPLICATION: 'APP' },
      },
      userLanguage: (prefData.userLanguage as LanguageCode) || 'en',
      appearanceTheme: (prefData.appearanceTheme as ThemeMode) || 'light',
      securityPolicy: (masterData.securityPolicy as MasterSettingsOverview['securityPolicy']) || {
        masterSettingsAccess: 'ADMIN_ONLY',
        userCreationAuthority: 'ADMIN_ONLY',
        approvalAuthority: 'ADMIN_ONLY',
        sessionDurationMinutes: 60,
        inactivityAutoLogoutMinutes: 60,
        passwordPolicy: 'Strong',
        failedLoginAttemptsLimit: 5,
        accountLockoutMinutes: 3,
        twoFactorRequiredRoles: ['ADMIN', 'MANAGER', 'STAFF'],
      },
      printSettings: (masterData.printSettings as MasterSettingsOverview['printSettings']) || {
        paperSize: 'A4',
        printMode: 'Print Preview then Print',
        includeLogo: true,
        includeDigitalSignature: true,
        includeCompanyStamp: true,
        defaultCopies: 1,
      },
      documentTemplates: Array.isArray(masterData.documentTemplates)
        ? (masterData.documentTemplates as MasterSettingsOverview['documentTemplates'])
        : [],
      paymentQrSettings: (masterData.paymentQrSettings as MasterSettingsOverview['paymentQrSettings']) || {
        cashEnabled: true,
        upiEnabled: true,
        otherEnabled: true,
        qrType: 'Static QR',
        qrOnReceipt: true,
        qrOnInvoice: true,
        manualVerificationRequired: true,
        upiId: '',
        staticQrPreviewUrl: '',
        dynamicQrProviderConfigured: false,
      },
      notificationTemplates: Array.isArray(masterData.notificationTemplates)
        ? (masterData.notificationTemplates as MasterSettingsOverview['notificationTemplates'])
        : [],
      branches: [
        {
          id: 1,
          branchCode: 'BR-MAIN',
          name: 'Main Service Center',
          address: 'Village Mamudpur (Chowmatha More), Domkal',
          pinCode: '742406',
          isDefault: true,
          status: 'active',
        },
      ],
      counters: [
        {
          id: 1,
          branchId: 1,
          counterCode: 'CNT-01',
          name: 'Counter 01 (Primary Desk)',
          assignedUserId: currentProfile.userId,
          status: 'active',
        },
      ],
      customerPrivacy: (masterData.customerPrivacy as MasterSettingsOverview['customerPrivacy']) || {
        duplicateCheckMobile: true,
        duplicateCheckAadhaar: true,
        consentMandatory: true,
        maskAadhaarByDefault: true,
        dataExportAdminOnly: true,
        retentionPolicy: '7 Years Statutory',
        declarationModes: ['Digital', 'Printed'],
        termsEditableByAdmin: 'All documents verified at counter.',
      },
      dashboardPreferences:
        (masterData.dashboardPreferences as MasterSettingsOverview['dashboardPreferences']) || {
          role:
            currentProfile.role === 'AUDITOR'
              ? 'MANAGER'
              : currentProfile.role === 'CUSTOMER' || currentProfile.role === 'EMPLOYEE'
              ? 'STAFF'
              : currentProfile.role,
          defaultPeriod: 'Today',
          enabledWidgets: [
            'Total Customers',
            'Total Applications',
            'Today Collection',
            'Pending Payments',
            'Total Expenses',
            'Today Profit',
            'Recent Activities',
            'Pending Approvals',
            'Service-wise Reports',
            'Monthly Collection',
          ],
        },
      reportSettings: (masterData.reportSettings as MasterSettingsOverview['reportSettings']) || {
        defaultExportFormat: 'PDF',
        autoDailyReportEnabled: false,
        autoReportTime: '20:00',
      },
      maintenanceSettings: (masterData.maintenanceSettings as MasterSettingsOverview['maintenanceSettings']) || {
        maintenanceMode: false,
        maintenanceMessage: '',
      },
      documentCounters: [],
      pendingProposalsCount: 0,
    };

    return okEnvelope(defaultOverview) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/master-settings/appearance' && method === 'PUT') {
    const theme = body.theme === 'dark' ? 'dark' : 'light';
    const prefRef = doc(db, 'settings', `pref_${uid}`);
    try {
      const snap = await getDoc(prefRef);
      if (snap.exists()) {
        await updateDoc(prefRef, {
          appearanceTheme: theme,
          updatedByUid: uid,
          updatedAt: serverTimestamp(),
        });
      } else {
        await setDoc(prefRef, {
          settingKey: `pref_${uid}`,
          appearanceTheme: theme,
          userLanguage: 'en',
          updatedByUid: uid,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
      }
      return okEnvelope({ theme }) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, `settings/pref_${uid}`);
    }
  }

  if (pathname === '/api/master-settings/user-language' && method === 'PUT') {
    const language = body.language === 'bn' || body.language === 'hi' ? body.language : 'en';
    const prefRef = doc(db, 'settings', `pref_${uid}`);
    try {
      const snap = await getDoc(prefRef);
      if (snap.exists()) {
        await updateDoc(prefRef, {
          userLanguage: language,
          updatedByUid: uid,
          updatedAt: serverTimestamp(),
        });
      } else {
        await setDoc(prefRef, {
          settingKey: `pref_${uid}`,
          userLanguage: language,
          appearanceTheme: 'light',
          updatedByUid: uid,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
      }
      return okEnvelope({ language }) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, `settings/pref_${uid}`);
    }
  }

  if (pathname === '/api/master-settings/company-profile' && method === 'PUT') {
    const masterRef = doc(db, 'settings', 'master');
    try {
      const snap = await getDoc(masterRef);
      if (snap.exists()) {
        await updateDoc(masterRef, {
          companyProfile: body,
          updatedByUid: uid,
          updatedAt: serverTimestamp(),
        });
      } else {
        await setDoc(masterRef, {
          settingKey: 'master',
          companyProfile: body,
          updatedByUid: uid,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
      }
      return okEnvelope(body, 'Company profile saved to Firestore.') as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, 'settings/master');
    }
  }

  // =========================================================================
  // DASHBOARD SUMMARY
  // =========================================================================
  if (pathname === '/api/erp/dashboard-summary' && method === 'GET') {
    const [customersRaw, appsRaw, paymentsRaw, expensesRaw] = await Promise.all([
      listCollectionScoped('customers'),
      listCollectionScoped('applications'),
      listCollectionScoped('payments'),
      listCollectionScoped('expenses'),
    ]);

    const customers = customersRaw.map(normalizeCustomerDoc).filter((c) => !c.deletedAt);
    const applications = appsRaw.map(normalizeApplicationDoc).filter((a) => !a.archivedAt);
    const payments = paymentsRaw.map(normalizePaymentDoc);
    const expenses = expensesRaw.map(normalizeExpenseDoc);

    const todayStr = new Date().toISOString().slice(0, 10);
    const totalCollection = payments
      .filter((p) => p.verificationStatus === 'Confirmed')
      .reduce((sum, p) => sum + p.amount, 0);
    const todayCollection = payments
      .filter((p) => p.verificationStatus === 'Confirmed' && p.recordedAt.startsWith(todayStr))
      .reduce((sum, p) => sum + p.amount, 0);
    const totalExpenses = expenses.reduce((sum, e) => sum + e.amount, 0);

    const breakdown: Record<string, number> = {};
    for (const app of applications) {
      breakdown[app.status] = (breakdown[app.status] || 0) + 1;
    }

    const summary: ErpDashboardSummary = {
      kpis: {
        totalCustomers: customers.length,
        totalApplications: applications.length,
        activeApplications: applications.filter((a) =>
          ['Submitted', 'Under Review', 'Processing', 'Pending Customer', 'Pending Office'].includes(a.status)
        ).length,
        pendingApplications: applications.filter((a) =>
          ['Draft', 'Submitted', 'Pending Customer', 'Pending Office'].includes(a.status)
        ).length,
        completedApplications: applications.filter((a) => a.status === 'Completed' || a.status === 'Approved').length,
        rejectedOrCancelled: applications.filter((a) => a.status === 'Rejected' || a.status === 'Cancelled').length,
        todayCollection,
        totalCollection,
        totalExpenses,
        netCashBalance: totalCollection - totalExpenses,
      },
      reminders: {
        pendingFollowUps: 0,
        missingOrPendingDocs: applications.filter((a) => a.checklistSummary.missingCount > 0).length,
        unassignedApplications: applications.filter((a) => !a.assignedStaffId).length,
        overdueSlaApplications: 0,
        pendingReassignments: 0,
        pendingCancellations: 0,
      },
      recentApplications: applications.slice(0, 10),
      recentPayments: payments.slice(0, 10),
      recentNotifications: [],
      applicationStatusBreakdown: breakdown,
    };

    return okEnvelope(summary) as ApiResponseEnvelope<T>;
  }

  // =========================================================================
  // CUSTOMERS CRM (LIVE FIRESTORE)
  // =========================================================================
  if (pathname === '/api/erp/customers' && method === 'GET') {
    const qText = (searchParams.get('q') || '').trim().toLowerCase();
    const statusFilter = searchParams.get('status') || '';
    const segmentFilter = searchParams.get('segment') || '';
    const includeDeleted = searchParams.get('includeDeleted') === 'true';

    const rawDocs = await listCollectionScoped('customers');
    const list = rawDocs
      .map(normalizeCustomerDoc)
      .filter((c) => (includeDeleted ? true : !c.deletedAt))
      .filter((c) => (!statusFilter ? true : c.status === statusFilter))
      .filter((c) => (!segmentFilter ? true : c.segment === segmentFilter))
      .filter((c) => {
        if (!qText) return true;
        return (
          c.customerId.toLowerCase().includes(qText) ||
          c.fullName.toLowerCase().includes(qText) ||
          c.mobile.toLowerCase().includes(qText) ||
          c.village.toLowerCase().includes(qText)
        );
      })
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    return okEnvelope(list) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/erp/customers' && method === 'POST') {
    const fullName = str(body.fullName, 120);
    const mobile = str(body.mobile, 24);
    const village = str(body.village, 120);

    if (fullName.length < 2) {
      failHttp('Customer full name must be at least 2 characters.', 422);
    }
    if (mobile.length < 8) {
      failHttp('Valid mobile number (minimum 8 digits) is required.', 422);
    }
    if (village.length < 1) {
      failHttp('Village / Town is required.', 422);
    }

    // Duplicate mobile check in Firestore unless override reason provided
    const overrideReason = str(body.overrideDuplicateReason, 200);
    const existingCustomers = (await listCollectionScoped('customers')).map(normalizeCustomerDoc);
    const normalizedMobile = mobile.replace(/[^\d]/g, '').slice(-10);
    const dup = existingCustomers.find(
      (c) => !c.deletedAt && c.mobile.replace(/[^\d]/g, '').slice(-10) === normalizedMobile
    );
    if (dup && !overrideReason) {
      failHttp(
        `Duplicate mobile number detected (${dup.customerId} — ${dup.fullName}). Provide an override reason to proceed.`,
        409
      );
    }

    const seq = await allocateSequence('CUST');
    const customerId = `CUST-${new Date().getFullYear()}-${String(seq).padStart(4, '0')}`;
    const rawAadhaar = str(body.aadhaarNumber, 20).replace(/\s|-/g, '');
    const aadhaarMasked =
      rawAadhaar.length >= 4 ? `XXXX-XXXX-${rawAadhaar.slice(-4)}` : undefined;

    const rawConsents = Array.isArray(body.consents) ? body.consents : [];
    const normalizedConsents = rawConsents.slice(0, 15).map((c: Record<string, unknown>) => ({
      category: str(c.category, 64),
      label: str(c.category, 64),
      granted: Boolean(c.granted),
      recordedAt: new Date().toISOString(),
      recordedBy: currentProfile.userId,
      verificationMethod: str(c.verificationMethod || 'Digital Signature', 64),
    }));

    const sameAsPresent = body.sameAsPresent !== false;
    const presentAddress = str(body.presentAddress, 300);
    const permanentAddress = sameAsPresent
      ? presentAddress
      : str(body.permanentAddress, 300);

    const genderRaw = str(body.gender, 16);
    const gender = (['Male', 'Female', 'Other'].includes(genderRaw) ? genderRaw : 'Male') as
      | 'Male'
      | 'Female'
      | 'Other';
    const segmentRaw = str(body.segment, 24);
    const segment = (
      ['Individual', 'Corporate', 'Government'].includes(segmentRaw) ? segmentRaw : 'Individual'
    ) as 'Individual' | 'Corporate' | 'Government';

    const docPayload: Record<string, unknown> = {
      id: seq,
      customerId,
      fullName,
      fatherOrHusbandName: str(body.fatherOrHusbandName, 120),
      dob: str(body.dob, 32),
      gender,
      mobile,
      whatsapp: str(body.whatsapp || mobile, 24),
      email: str(body.email, 160),
      ...(aadhaarMasked ? { aadhaarMasked } : {}),
      panNumber: str(body.panNumber, 20).toUpperCase(),
      voterId: str(body.voterId, 32).toUpperCase(),
      village,
      postOffice: str(body.postOffice, 120),
      policeStation: str(body.policeStation, 120),
      district: str(body.district || 'Murshidabad', 120),
      pinCode: str(body.pinCode, 16),
      presentAddress,
      permanentAddress,
      sameAsPresent,
      segment,
      crmTag: 'Standard',
      status: 'Active',
      verificationStatus: 'Verified at Counter',
      mobileOtpVerifiedAt: null,
      consents: normalizedConsents,
      consentHistory: [],
      contactHistory: [],
      notesAndFollowUps: [],
      deletedAt: null,
      createdByUid: uid,
      createdBy: currentProfile.userId,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };

    try {
      await setDoc(doc(db, 'customers', customerId), docPayload);
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `customers/${customerId}`);
    }

    await writeSecurityLog(
      'CUSTOMER_CREATED',
      currentProfile.userId,
      `Registered customer ${customerId} (${fullName}) in Firestore.`
    );

    const savedSnap = await getDoc(doc(db, 'customers', customerId));
    return okEnvelope(
      normalizeCustomerDoc(savedSnap.data() as Record<string, unknown>),
      'Customer registered in Firebase Firestore.'
    ) as ApiResponseEnvelope<T>;
  }

  const customerProfileMatch = pathname.match(/^\/api\/erp\/customers\/([^/]+)$/);
  if (customerProfileMatch && method === 'GET') {
    const customerId = decodeURIComponent(customerProfileMatch[1]);
    try {
      const cSnap = await getDoc(doc(db, 'customers', customerId));
      if (!cSnap.exists()) failHttp('Customer not found.', 404);
      const customer = normalizeCustomerDoc(cSnap.data() as Record<string, unknown>);
      const apps = (await listCollectionScoped('applications'))
        .map(normalizeApplicationDoc)
        .filter((a) => a.customerId === customerId);
      const payments = (await listCollectionScoped('payments'))
        .map(normalizePaymentDoc)
        .filter((p) => p.customerId === customerId);
      const refunds = (await listCollectionScoped('refunds'))
        .map(normalizeRefundDoc)
        .filter((r) => r.customerId === customerId);

      return okEnvelope({
        customer,
        applications: apps,
        documents: [],
        payments,
        refunds,
        deliveries: [],
        followUps: [],
        notifications: [],
      }) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.GET, `customers/${customerId}`);
    }
  }

  const customerNotesMatch = pathname.match(/^\/api\/erp\/customers\/([^/]+)\/notes$/);
  if (customerNotesMatch && method === 'POST') {
    const customerId = decodeURIComponent(customerNotesMatch[1]);
    const cRef = doc(db, 'customers', customerId);
    try {
      const snap = await getDoc(cRef);
      if (!snap.exists()) failHttp('Customer not found.', 404);
      const current = normalizeCustomerDoc(snap.data() as Record<string, unknown>);
      const nextNotes = [
        {
          id: Date.now(),
          type: body.type === 'FOLLOW_UP' ? 'FOLLOW_UP' : 'INTERNAL_NOTE',
          text: str(body.text, 250),
          followUpDate: body.followUpDate ? str(body.followUpDate, 32) : undefined,
          status: 'Open',
          authorUserId: currentProfile.userId,
          createdAt: new Date().toISOString(),
        },
        ...current.notesAndFollowUps,
      ].slice(0, 100);
      await updateDoc(cRef, {
        notesAndFollowUps: nextNotes,
        updatedAt: serverTimestamp(),
      });
      const updated = await getDoc(cRef);
      return okEnvelope(normalizeCustomerDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `customers/${customerId}`);
    }
  }

  if (customerProfileMatch && method === 'PUT') {
    const customerId = decodeURIComponent(customerProfileMatch[1]);
    const cRef = doc(db, 'customers', customerId);
    try {
      const snap = await getDoc(cRef);
      if (!snap.exists()) failHttp('Customer not found.', 404);
      const patch: Record<string, unknown> = { updatedAt: serverTimestamp() };
      const stringFields: Array<[string, number]> = [
        ['fullName', 120],
        ['fatherOrHusbandName', 120],
        ['dob', 32],
        ['mobile', 24],
        ['whatsapp', 24],
        ['email', 160],
        ['panNumber', 20],
        ['voterId', 32],
        ['village', 120],
        ['postOffice', 120],
        ['policeStation', 120],
        ['district', 120],
        ['pinCode', 16],
        ['presentAddress', 300],
        ['permanentAddress', 300],
        ['crmTag', 64],
      ];
      for (const [key, max] of stringFields) {
        if (key in body) patch[key] = str(body[key], max);
      }
      if ('gender' in body && ['Male', 'Female', 'Other'].includes(String(body.gender))) {
        patch.gender = body.gender;
      }
      if ('segment' in body && ['Individual', 'Corporate', 'Government'].includes(String(body.segment))) {
        patch.segment = body.segment;
      }
      if ('sameAsPresent' in body) {
        patch.sameAsPresent = Boolean(body.sameAsPresent);
      }
      await updateDoc(cRef, patch);
      const updated = await getDoc(cRef);
      return okEnvelope(normalizeCustomerDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `customers/${customerId}`);
    }
  }

  const customerConsentsMatch = pathname.match(/^\/api\/erp\/customers\/([^/]+)\/consents$/);
  if (customerConsentsMatch && method === 'PUT') {
    const customerId = decodeURIComponent(customerConsentsMatch[1]);
    const cRef = doc(db, 'customers', customerId);
    try {
      const snap = await getDoc(cRef);
      if (!snap.exists()) failHttp('Customer not found.', 404);
      const current = normalizeCustomerDoc(snap.data() as Record<string, unknown>);
      const updates = Array.isArray(body.updates)
        ? (body.updates as Array<{ category: string; granted: boolean }>)
        : [];
      const verificationMethod = str(
        body.verificationMethod || 'Digital Signature',
        64
      ) as CustomerConsentState['verificationMethod'];
      const nowIso = new Date().toISOString();

      const consentsMap = new Map<ConsentCategoryKey, CustomerConsentState>(
        current.consents.map((c) => [c.category, { ...c }])
      );
      const historyAdds = [];
      for (const u of updates) {
        const cat = str(u.category, 64) as ConsentCategoryKey;
        const granted = Boolean(u.granted);
        const existingItem = consentsMap.get(cat);
        consentsMap.set(cat, {
          category: cat,
          label: existingItem?.label || cat,
          granted,
          recordedAt: nowIso,
          recordedBy: currentProfile.userId,
          verificationMethod,
        });
        historyAdds.push({
          id: Date.now() + historyAdds.length,
          category: cat,
          action: granted ? 'Granted' : 'Revoked',
          method: verificationMethod,
          changedBy: currentProfile.userId,
          changedAt: nowIso,
          notes: str(body.notes, 200),
        });
      }
      await updateDoc(cRef, {
        consents: Array.from(consentsMap.values()).slice(0, 15),
        consentHistory: [...historyAdds, ...current.consentHistory].slice(0, 100),
        updatedAt: serverTimestamp(),
      });
      const updated = await getDoc(cRef);
      return okEnvelope(normalizeCustomerDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `customers/${customerId}`);
    }
  }

  const customerSoftDeleteMatch = pathname.match(/^\/api\/erp\/customers\/([^/]+)\/soft-delete$/);
  if (customerSoftDeleteMatch && method === 'POST') {
    const customerId = decodeURIComponent(customerSoftDeleteMatch[1]);
    const cRef = doc(db, 'customers', customerId);
    try {
      const snap = await getDoc(cRef);
      if (!snap.exists()) failHttp('Customer not found.', 404);
      await updateDoc(cRef, {
        deletedAt: new Date().toISOString(),
        status: 'Inactive',
        updatedAt: serverTimestamp(),
      });
      return okEnvelope({ archived: true }, 'Customer archived in Firestore.') as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `customers/${customerId}`);
    }
  }

  const customerRestoreMatch = pathname.match(/^\/api\/erp\/customers\/([^/]+)\/restore$/);
  if (customerRestoreMatch && method === 'POST') {
    const customerId = decodeURIComponent(customerRestoreMatch[1]);
    const cRef = doc(db, 'customers', customerId);
    try {
      const snap = await getDoc(cRef);
      if (!snap.exists()) failHttp('Customer not found.', 404);
      await updateDoc(cRef, {
        deletedAt: null,
        status: 'Active',
        updatedAt: serverTimestamp(),
      });
      const updated = await getDoc(cRef);
      return okEnvelope(normalizeCustomerDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `customers/${customerId}`);
    }
  }

  if (pathname === '/api/erp/customers/bulk-import' && method === 'POST') {
    const rows = Array.isArray(body.rows) ? (body.rows as Array<Record<string, unknown>>) : [];
    const commit = Boolean(body.commit);
    const existingCustomers = (await listCollectionScoped('customers')).map(normalizeCustomerDoc);
    const seenMobiles = new Set(
      existingCustomers.filter((c) => !c.deletedAt).map((c) => c.mobile.replace(/[^\d]/g, '').slice(-10))
    );

    const preview = rows.map((row, idx) => {
      const fullName = str(row.fullName, 120);
      const mobile = str(row.mobile, 24);
      const village = str(row.village, 120);
      const errors: string[] = [];
      if (fullName.length < 2) errors.push('Name < 2 chars');
      if (mobile.length < 8) errors.push('Invalid mobile');
      if (!village) errors.push('Village missing');
      const normMob = mobile.replace(/[^\d]/g, '').slice(-10);
      if (normMob && seenMobiles.has(normMob)) errors.push('Duplicate mobile');
      if (normMob && errors.length === 0) seenMobiles.add(normMob);
      return { rowNumber: idx + 1, fullName, mobile, village, valid: errors.length === 0, errors };
    });

    const createdIds: string[] = [];
    if (commit) {
      for (let i = 0; i < preview.length; i += 1) {
        const p = preview[i];
        if (!p.valid) continue;
        const row = rows[i];
        const seq = await allocateSequence('CUST');
        const customerId = `CUST-${new Date().getFullYear()}-${String(seq).padStart(4, '0')}`;
        try {
          await setDoc(doc(db, 'customers', customerId), {
            id: seq,
            customerId,
            fullName: p.fullName,
            fatherOrHusbandName: '',
            dob: '',
            gender: 'Male',
            mobile: p.mobile,
            whatsapp: p.mobile,
            email: str(row.email, 160),
            village: p.village,
            postOffice: '',
            policeStation: '',
            district: str(row.district || 'Murshidabad', 120),
            pinCode: '',
            presentAddress: p.village,
            permanentAddress: p.village,
            sameAsPresent: true,
            segment: 'Individual',
            crmTag: 'Standard',
            status: 'Active',
            verificationStatus: 'Verified at Counter',
            mobileOtpVerifiedAt: null,
            consents: [],
            consentHistory: [],
            contactHistory: [],
            notesAndFollowUps: [],
            deletedAt: null,
            createdByUid: uid,
            createdBy: currentProfile.userId,
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp(),
          });
          createdIds.push(customerId);
        } catch (err) {
          handleFirestoreError(err, OperationType.CREATE, `customers/${customerId}`);
        }
      }
    }

    return okEnvelope(
      {
        mode: commit ? 'COMMITTED' : 'PREVIEW',
        totalRows: rows.length,
        validCount: preview.filter((p) => p.valid).length,
        invalidCount: preview.filter((p) => !p.valid).length,
        createdIds,
        preview,
      },
      commit ? `Imported ${createdIds.length} customer(s) to Firestore.` : 'Preview ready'
    ) as ApiResponseEnvelope<T>;
  }

  // =========================================================================
  // SERVICE CATEGORIES, SUBCATEGORIES & SERVICES (LIVE FIRESTORE)
  // =========================================================================
  const isAdminOrManagerUser =
    isBootAdmin || currentProfile.role === 'ADMIN' || currentProfile.role === 'MANAGER';

  if (pathname === '/api/erp/services/sync-catalog' && method === 'POST') {
    if (!isAdminOrManagerUser) {
      failHttp('Only Admin or Manager can sync the 675 Services catalog to Firestore.', 403);
    }
    const result = await syncCatalog675ToFirestore(uid, currentProfile.userId);
    await writeSecurityLog(
      'SERVICES_CATALOG_SYNCED',
      currentProfile.userId,
      `Synced ${result.categoriesCount} categories, ${result.subcategoriesCount} subcategories, ${result.servicesCount} services (${result.codeRange}) to Firestore.`
    );
    return okEnvelope(
      result,
      `Synced ${result.servicesCount} services (${result.codeRange}) across ${result.categoriesCount} categories and ${result.subcategoriesCount} subcategories.`
    ) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/erp/service-categories' && method === 'GET') {
    if (isAdminOrManagerUser) {
      await ensureCatalogSeededIfEmpty(uid, currentProfile.userId);
    }
    const raw = await listCollectionScoped('serviceCategories');
    const items: ServiceCategoryItem[] = raw
      .map((r, idx) => normalizeCategoryDoc(r, idx))
      .filter((c) => !LEGACY_MOCK_CATEGORY_IDS.includes(c.code))
      .sort((a, b) => (a.displayOrder ?? a.id) - (b.displayOrder ?? b.id) || a.id - b.id);
    return okEnvelope(items) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/erp/service-categories' && method === 'POST') {
    if (!isAdminOrManagerUser) failHttp('Only Admin or Manager can create Service Categories.', 403);
    const name = str(body.name, 120);
    if (name.length < 2) failHttp('Category name must be at least 2 characters.', 422);

    const existingRaw = await listCollectionScoped('serviceCategories');
    const dup = existingRaw.find((c) => String(c.name || '').toLowerCase() === name.toLowerCase());
    if (dup) failHttp('Service Category name already exists.', 409);

    const maxExistingId = existingRaw.reduce((m, c) => Math.max(m, Number(c.id || 0)), 0);
    await ensureSequenceAtLeast('CAT', maxExistingId, uid);
    let seq = await allocateSequence('CAT');
    let code = `CAT-${String(seq).padStart(2, '0')}`;
    try {
      while ((await getDoc(doc(db, 'serviceCategories', code))).exists()) {
        seq = await allocateSequence('CAT');
        code = `CAT-${String(seq).padStart(2, '0')}`;
      }
      const displayOrder =
        body.displayOrder !== undefined && Number.isFinite(Number(body.displayOrder))
          ? Number(body.displayOrder)
          : seq;
      await setDoc(doc(db, 'serviceCategories', code), {
        id: seq,
        code,
        name,
        description: str(body.description, 400),
        displayOrder,
        status: 'active',
        proposedBy: currentProfile.userId,
        approvedBy: currentProfile.userId,
        createdBy: currentProfile.userId,
        updatedBy: currentProfile.userId,
        createdByUid: uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
      return okEnvelope({
        id: seq,
        code,
        name,
        description: str(body.description, 400),
        displayOrder,
        status: 'active',
        proposedBy: currentProfile.userId,
        approvedBy: currentProfile.userId,
        createdBy: currentProfile.userId,
        updatedBy: currentProfile.userId,
      }) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.CREATE, `serviceCategories/${code}`);
    }
  }

  const catApproveMatch = pathname.match(/^\/api\/erp\/service-categories\/([^/]+)\/approve$/);
  if (catApproveMatch && method === 'POST') {
    if (!isAdminOrManagerUser) failHttp('Only Admin or Manager can approve categories.', 403);
    const idParam = decodeURIComponent(catApproveMatch[1]);
    const rawCats = await listCollectionScoped('serviceCategories');
    const matched = rawCats.find((c) => String(c.id) === idParam || String(c.code) === idParam);
    if (!matched) failHttp('Category not found.', 404);
    const code = String(matched.code);
    const nextStatus = body.action === 'ARCHIVE' ? 'archived' : 'active';
    try {
      await updateDoc(doc(db, 'serviceCategories', code), {
        status: nextStatus,
        approvedBy: currentProfile.userId,
        updatedBy: currentProfile.userId,
        updatedAt: serverTimestamp(),
      });
      const updated = await getDoc(doc(db, 'serviceCategories', code));
      return okEnvelope(normalizeCategoryDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.UPDATE, `serviceCategories/${code}`);
    }
  }

  const catUpdateDeleteMatch = pathname.match(/^\/api\/erp\/service-categories\/([^/]+)$/);
  if (catUpdateDeleteMatch && method === 'PUT') {
    if (!isAdminOrManagerUser) failHttp('Only Admin or Manager can edit Service Categories.', 403);
    const idParam = decodeURIComponent(catUpdateDeleteMatch[1]);
    const rawCats = await listCollectionScoped('serviceCategories');
    const matched = rawCats.find((c) => String(c.id) === idParam || String(c.code) === idParam);
    if (!matched) failHttp('Category not found.', 404);
    const code = String(matched.code);
    const nextName = typeof body.name === 'string' ? str(body.name, 120) : String(matched.name);
    if (nextName.length < 2) failHttp('Category name must be at least 2 characters.', 422);
    const dup = rawCats.find(
      (c) => String(c.code) !== code && String(c.name || '').toLowerCase() === nextName.toLowerCase()
    );
    if (dup) failHttp('Another Service Category already uses this name.', 409);

    try {
      await updateDoc(doc(db, 'serviceCategories', code), {
        name: nextName,
        description: typeof body.description === 'string' ? str(body.description, 400) : String(matched.description || ''),
        displayOrder:
          body.displayOrder !== undefined && Number.isFinite(Number(body.displayOrder))
            ? Number(body.displayOrder)
            : Number(matched.displayOrder ?? matched.id ?? 1),
        status: ['active', 'pending_approval', 'archived'].includes(String(body.status))
          ? String(body.status)
          : String(matched.status || 'active'),
        updatedBy: currentProfile.userId,
        updatedAt: serverTimestamp(),
      });
      const updated = await getDoc(doc(db, 'serviceCategories', code));
      return okEnvelope(normalizeCategoryDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.UPDATE, `serviceCategories/${code}`);
    }
  }

  if (catUpdateDeleteMatch && method === 'DELETE') {
    if (!isAdminOrManagerUser) failHttp('Only Admin or Manager can delete Service Categories.', 403);
    const idParam = decodeURIComponent(catUpdateDeleteMatch[1]);
    const rawCats = await listCollectionScoped('serviceCategories');
    const matched = rawCats.find((c) => String(c.id) === idParam || String(c.code) === idParam);
    if (!matched) failHttp('Category not found.', 404);
    const catIdNum = Number(matched.id);
    const code = String(matched.code);
    const [subs, svcs] = await Promise.all([
      listCollectionScoped('serviceSubcategories'),
      listCollectionScoped('services'),
    ]);
    if (subs.some((sc) => Number(sc.categoryId) === catIdNum)) {
      failHttp('Cannot delete category while subcategories are linked to it.', 409);
    }
    if (svcs.some((s) => Number(s.categoryId) === catIdNum && !s.deletedAt)) {
      failHttp('Cannot delete category while services are linked to it.', 409);
    }
    try {
      await deleteDoc(doc(db, 'serviceCategories', code));
      return okEnvelope({ deleted: true, id: catIdNum }) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.DELETE, `serviceCategories/${code}`);
    }
  }

  if (pathname === '/api/erp/service-subcategories' && method === 'GET') {
    if (isAdminOrManagerUser) {
      await ensureCatalogSeededIfEmpty(uid, currentProfile.userId);
    }
    const categoryId = searchParams.get('categoryId') ? Number(searchParams.get('categoryId')) : null;
    const raw = await listCollectionScoped('serviceSubcategories');
    const items: ServiceSubcategoryItem[] = raw
      .map((r, idx) => normalizeSubcategoryDoc(r, idx))
      .filter((sc) => (categoryId ? sc.categoryId === categoryId : true))
      .sort(
        (a, b) =>
          a.categoryId - b.categoryId ||
          (a.displayOrder ?? a.id) - (b.displayOrder ?? b.id) ||
          a.id - b.id
      );
    return okEnvelope(items) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/erp/service-subcategories' && method === 'POST') {
    if (!isAdminOrManagerUser) failHttp('Only Admin or Manager can create Service Subcategories.', 403);
    const categoryId = Number(body.categoryId);
    const name = str(body.name, 120);
    if (name.length < 2) failHttp('Subcategory name must be at least 2 characters.', 422);

    const [cats, subs] = await Promise.all([
      listCollectionScoped('serviceCategories'),
      listCollectionScoped('serviceSubcategories'),
    ]);
    const parentCat = cats.find((c) => Number(c.id) === categoryId);
    if (!parentCat) failHttp('Valid parent Category ID is required.', 422);
    if (subs.some((sc) => Number(sc.categoryId) === categoryId && String(sc.name || '').toLowerCase() === name.toLowerCase())) {
      failHttp(`Subcategory "${name}" already exists under ${parentCat.name}.`, 409);
    }

    const maxExistingId = subs.reduce((m, sc) => Math.max(m, Number(sc.id || 0)), 0);
    await ensureSequenceAtLeast('SUB', maxExistingId, uid);
    let seq = await allocateSequence('SUB');
    let code = `SUB-${String(categoryId).padStart(2, '0')}-${String(seq).padStart(3, '0')}`;
    try {
      while ((await getDoc(doc(db, 'serviceSubcategories', code))).exists()) {
        seq = await allocateSequence('SUB');
        code = `SUB-${String(categoryId).padStart(2, '0')}-${String(seq).padStart(3, '0')}`;
      }
      const countInCat = subs.filter((sc) => Number(sc.categoryId) === categoryId).length + 1;
      const displayOrder =
        body.displayOrder !== undefined && Number.isFinite(Number(body.displayOrder))
          ? Number(body.displayOrder)
          : countInCat;
      await setDoc(doc(db, 'serviceSubcategories', code), {
        id: seq,
        code,
        categoryId,
        categoryName: String(parentCat.name || ''),
        name,
        description: str(body.description, 400),
        displayOrder,
        status: 'active',
        createdBy: currentProfile.userId,
        updatedBy: currentProfile.userId,
        createdByUid: uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
      const snap = await getDoc(doc(db, 'serviceSubcategories', code));
      return okEnvelope(normalizeSubcategoryDoc(snap.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.CREATE, `serviceSubcategories/${code}`);
    }
  }

  const subUpdateDeleteMatch = pathname.match(/^\/api\/erp\/service-subcategories\/([^/]+)$/);
  if (subUpdateDeleteMatch && method === 'PUT') {
    if (!isAdminOrManagerUser) failHttp('Only Admin or Manager can edit Service Subcategories.', 403);
    const idParam = decodeURIComponent(subUpdateDeleteMatch[1]);
    const [cats, subs] = await Promise.all([
      listCollectionScoped('serviceCategories'),
      listCollectionScoped('serviceSubcategories'),
    ]);
    const matched = subs.find((sc) => String(sc.id) === idParam || String(sc.code) === idParam);
    if (!matched) failHttp('Subcategory not found.', 404);
    const code = String(matched.code);
    const targetCategoryId =
      body.categoryId !== undefined ? Number(body.categoryId) : Number(matched.categoryId);
    const parentCat = cats.find((c) => Number(c.id) === targetCategoryId);
    if (!parentCat) failHttp('Valid parent Category ID is required.', 422);

    const nextName = typeof body.name === 'string' ? str(body.name, 120) : String(matched.name);
    if (nextName.length < 2) failHttp('Subcategory name must be at least 2 characters.', 422);
    if (
      subs.some(
        (sc) =>
          String(sc.code) !== code &&
          Number(sc.categoryId) === targetCategoryId &&
          String(sc.name || '').toLowerCase() === nextName.toLowerCase()
      )
    ) {
      failHttp(`Subcategory "${nextName}" already exists under ${parentCat.name}.`, 409);
    }

    try {
      await updateDoc(doc(db, 'serviceSubcategories', code), {
        categoryId: targetCategoryId,
        categoryName: String(parentCat.name || ''),
        name: nextName,
        description:
          typeof body.description === 'string'
            ? str(body.description, 400)
            : String(matched.description || ''),
        displayOrder:
          body.displayOrder !== undefined && Number.isFinite(Number(body.displayOrder))
            ? Number(body.displayOrder)
            : Number(matched.displayOrder ?? matched.id ?? 1),
        status: ['active', 'archived'].includes(String(body.status))
          ? String(body.status)
          : String(matched.status || 'active'),
        updatedBy: currentProfile.userId,
        updatedAt: serverTimestamp(),
      });
      const updated = await getDoc(doc(db, 'serviceSubcategories', code));
      return okEnvelope(normalizeSubcategoryDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.UPDATE, `serviceSubcategories/${code}`);
    }
  }

  if (subUpdateDeleteMatch && method === 'DELETE') {
    if (!isAdminOrManagerUser) failHttp('Only Admin or Manager can delete Service Subcategories.', 403);
    const idParam = decodeURIComponent(subUpdateDeleteMatch[1]);
    const [subs, svcs] = await Promise.all([
      listCollectionScoped('serviceSubcategories'),
      listCollectionScoped('services'),
    ]);
    const matched = subs.find((sc) => String(sc.id) === idParam || String(sc.code) === idParam);
    if (!matched) failHttp('Subcategory not found.', 404);
    const subIdNum = Number(matched.id);
    const code = String(matched.code);
    if (svcs.some((s) => Number(s.subcategoryId) === subIdNum && !s.deletedAt)) {
      failHttp('Cannot delete subcategory while services are linked to it.', 409);
    }
    try {
      await deleteDoc(doc(db, 'serviceSubcategories', code));
      return okEnvelope({ deleted: true, id: subIdNum }) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.DELETE, `serviceSubcategories/${code}`);
    }
  }

  if (pathname === '/api/erp/services' && method === 'GET') {
    if (isAdminOrManagerUser) {
      await ensureCatalogSeededIfEmpty(uid, currentProfile.userId);
    }
    const includeDeleted = searchParams.get('includeDeleted') === 'true';
    const raw = await listCollectionScoped('services');
    const items = raw
      .map(normalizeServiceDoc)
      .filter((s) => !LEGACY_MOCK_SERVICE_IDS.includes(s.serviceId))
      .filter((s) => (includeDeleted ? true : !s.deletedAt))
      .sort((a, b) => (a.displayOrder ?? a.id) - (b.displayOrder ?? b.id) || a.id - b.id);
    return okEnvelope(items) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/erp/services' && method === 'POST') {
    if (!isAdminOrManagerUser) {
      failHttp('Only Admin or Manager can create master service offerings.', 403);
    }
    const name = str(body.name, 160);
    if (name.length < 2) {
      failHttp('Service name must be at least 2 characters.', 422);
    }

    const round2 = (n: number) => Math.round((n + Number.EPSILON) * 100) / 100;
    const serviceCharge = Number(
      body.serviceCharge !== undefined ? body.serviceCharge : body.customerCharge ?? 0
    );
    const serviceCost = Number(body.serviceCost ?? 0);
    const govtFee = Number(body.govtFee ?? 0);
    const additionalCharges = Number(body.additionalCharges ?? 0);

    if (
      !Number.isFinite(serviceCharge) ||
      serviceCharge < 0 ||
      !Number.isFinite(serviceCost) ||
      serviceCost < 0 ||
      !Number.isFinite(govtFee) ||
      govtFee < 0 ||
      !Number.isFinite(additionalCharges) ||
      additionalCharges < 0
    ) {
      failHttp('Service charge, cost, government fee, and additional charges must be valid numbers >= 0.', 422);
    }

    const totalCustomerCharge = round2(serviceCharge + govtFee + additionalCharges);
    const profitAmount = round2(serviceCharge + additionalCharges - serviceCost);

    const [cats, subs, svcs] = await Promise.all([
      listCollectionScoped('serviceCategories'),
      listCollectionScoped('serviceSubcategories'),
      listCollectionScoped('services'),
    ]);

    const categoryId = Number(body.categoryId || cats[0]?.id || 1);
    const matchedCat = cats.find((c) => Number(c.id) === categoryId);
    const categoryName = str(body.categoryName, 120) || String(matchedCat?.name || 'General');

    let subcategoryId: number | undefined;
    let subcategoryName: string | undefined;
    if (body.subcategoryId !== undefined && body.subcategoryId !== null && body.subcategoryId !== '') {
      const matchedSub = subs.find(
        (sc) => Number(sc.id) === Number(body.subcategoryId) && Number(sc.categoryId) === categoryId
      );
      if (!matchedSub) {
        failHttp('Selected Subcategory does not belong to the chosen Category.', 422);
      }
      subcategoryId = Number(matchedSub.id);
      subcategoryName = String(matchedSub.name || '');
    } else {
      const firstSub = subs.find((sc) => Number(sc.categoryId) === categoryId);
      if (firstSub) {
        subcategoryId = Number(firstSub.id);
        subcategoryName = String(firstSub.name || '');
      }
    }

    const dup = svcs.find(
      (s) =>
        !s.deletedAt &&
        Number(s.categoryId) === categoryId &&
        (subcategoryId ? Number(s.subcategoryId) === subcategoryId : true) &&
        String(s.name || '').toLowerCase() === name.toLowerCase()
    );
    if (dup) {
      failHttp(`Service "${name}" already exists in this category/subcategory (${dup.serviceCode}).`, 409);
    }

    const fyCode = resolveFinancialYearCodeIST();
    const fyFormatted = `${fyCode.slice(0, 2)}-${fyCode.slice(2, 4)}`;
    const maxIdNum = svcs.reduce((m, s) => {
      const numericId = Number(s.id || 0);
      const codeMatch = String(s.serviceCode || '').match(/SRV-(\d+)$/);
      const codeNum = codeMatch ? Number(codeMatch[1]) : 0;
      const idMatch = String(s.serviceId || '').match(/-(\d+)$/);
      const idNum = idMatch ? Number(idMatch[1]) : 0;
      return Math.max(m, numericId, codeNum, idNum);
    }, 0);

    await Promise.all([
      ensureSequenceAtLeast(`MCS_${fyCode}`, maxIdNum, uid),
      ensureSequenceAtLeast(`SRV_${fyCode}`, maxIdNum, uid),
    ]);

    let mcsSeq = await allocateSequence(`MCS_${fyCode}`);
    let serviceId = `MCS-20${fyFormatted}-${String(mcsSeq).padStart(6, '0')}`;
    let srvSeq = await allocateSequence(`SRV_${fyCode}`);
    let serviceCode = `MC${fyCode}SRV-${String(srvSeq).padStart(3, '0')}`;

    try {
      while ((await getDoc(doc(db, 'services', serviceId))).exists()) {
        mcsSeq = await allocateSequence(`MCS_${fyCode}`);
        serviceId = `MCS-20${fyFormatted}-${String(mcsSeq).padStart(6, '0')}`;
      }
      while (svcs.some((s) => String(s.serviceCode) === serviceCode)) {
        srvSeq = await allocateSequence(`SRV_${fyCode}`);
        serviceCode = `MC${fyCode}SRV-${String(srvSeq).padStart(3, '0')}`;
      }

      const defaultFields = Array.isArray(body.fields) && body.fields.length > 0
        ? body.fields
        : [
            {
              fieldKey: 'applicant_name',
              label: 'Applicant Full Name',
              fieldType: 'short_text',
              required: true,
              displayOrder: 1,
              enabled: true,
            },
            {
              fieldKey: 'applicant_mobile',
              label: 'Mobile Number',
              fieldType: 'mobile',
              required: true,
              displayOrder: 2,
              enabled: true,
            },
            {
              fieldKey: 'service_notes',
              label: 'Service Request Notes / Details',
              fieldType: 'long_text',
              required: false,
              displayOrder: 3,
              enabled: true,
            },
          ];

      const instructions = str(
        body.serviceInstructions ||
          body.termsAndConditions ||
          'MUN COMPUTER provides private filing & digital assistance; statutory outcomes are governed by respective authorities.',
        2000
      );
      const status = body.status === 'Inactive' ? 'Inactive' : 'Active';
      const availability = status === 'Active' ? String(body.availability || 'Available') : 'Unavailable';

      const payload: Record<string, unknown> = {
        id: mcsSeq,
        serviceId,
        serviceCode,
        name,
        categoryId,
        categoryName,
        ...(subcategoryId !== undefined ? { subcategoryId, subcategoryName } : {}),
        description: str(body.description, 600),
        serviceCharge: round2(serviceCharge),
        serviceCost: round2(serviceCost),
        govtFee: round2(govtFee),
        additionalCharges: round2(additionalCharges),
        totalCustomerCharge,
        customerCharge: totalCustomerCharge,
        profitAmount,
        status,
        availability,
        serviceInstructions: instructions,
        termsAndConditions: instructions,
        displayOrder:
          body.displayOrder !== undefined && Number.isFinite(Number(body.displayOrder))
            ? Number(body.displayOrder)
            : maxIdNum + 1,
        sla: body.sla || {
          processingMode: 'FIXED',
          expectedDays: 3,
          minDays: 1,
          maxDays: 5,
          dayType: 'WORKING',
          excludeHolidays: true,
          startEvent: 'ON_SUBMIT',
          pauseOnStatuses: ['Pending Customer', 'Pending Office', 'On Hold'],
          warningThresholdPct: 75,
          breachThresholdHours: 72,
        },
        requiredDocuments: Array.isArray(body.requiredDocuments) ? body.requiredDocuments.slice(0, 30) : [],
        currentFormVersion: 1,
        formVersions: [
          {
            versionNo: 1,
            publishedAt: new Date().toISOString(),
            publishedBy: currentProfile.userId,
            status: 'published',
            fields: defaultFields,
          },
        ],
        automationRules: Array.isArray(body.automationRules) ? body.automationRules.slice(0, 20) : [],
        processingTimeHistory: [],
        deletedAt: null,
        createdBy: currentProfile.userId,
        updatedBy: currentProfile.userId,
        createdByUid: uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      };

      await setDoc(doc(db, 'services', serviceId), payload);
      const snap = await getDoc(doc(db, 'services', serviceId));
      return okEnvelope(normalizeServiceDoc(snap.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.CREATE, `services/${serviceId}`);
    }
  }

  const resolveServiceDocRef = async (idOrCode: string) => {
    const directRef = doc(db, 'services', idOrCode);
    const directSnap = await getDoc(directRef);
    if (directSnap.exists()) {
      return { ref: directRef, snap: directSnap };
    }
    const q = query(collection(db, 'services'), where('serviceCode', '==', idOrCode));
    const qSnap = await getDocs(q);
    if (!qSnap.empty) {
      const matchedDoc = qSnap.docs[0];
      return { ref: doc(db, 'services', matchedDoc.id), snap: matchedDoc };
    }
    return null;
  };

  const serviceStatusMatch = pathname.match(/^\/api\/erp\/services\/([^/]+)\/status$/);
  if (serviceStatusMatch && method === 'PATCH') {
    if (!isAdminOrManagerUser) failHttp('Only Admin or Manager can update service status.', 403);
    const serviceIdParam = decodeURIComponent(serviceStatusMatch[1]);
    try {
      const found = await resolveServiceDocRef(serviceIdParam);
      if (!found) failHttp('Service not found.', 404);
      const nextStatus = body.status === 'Inactive' ? 'Inactive' : 'Active';
      const nextAvailability = nextStatus === 'Active' ? 'Available' : 'Unavailable';
      await updateDoc(found.ref, {
        status: nextStatus,
        availability: nextAvailability,
        updatedBy: currentProfile.userId,
        updatedAt: serverTimestamp(),
      });
      const updated = await getDoc(found.ref);
      return okEnvelope(normalizeServiceDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `services/${serviceIdParam}`);
    }
  }

  const serviceUpdateMatch = pathname.match(/^\/api\/erp\/services\/([^/]+)$/);
  if (serviceUpdateMatch && method === 'PUT') {
    if (!isAdminOrManagerUser) failHttp('Only Admin or Manager can update services.', 403);
    const serviceIdParam = decodeURIComponent(serviceUpdateMatch[1]);
    try {
      const found = await resolveServiceDocRef(serviceIdParam);
      if (!found) failHttp('Service not found.', 404);
      const current = normalizeServiceDoc(found.snap.data() as Record<string, unknown>);
      const round2 = (n: number) => Math.round((n + Number.EPSILON) * 100) / 100;

      const nextServiceCharge =
        'serviceCharge' in body
          ? Number(body.serviceCharge)
          : 'customerCharge' in body && !('govtFee' in body) && !('additionalCharges' in body)
            ? Number(body.customerCharge)
            : current.serviceCharge;
      const nextServiceCost =
        'serviceCost' in body ? Number(body.serviceCost) : current.serviceCost;
      const nextGovtFee = 'govtFee' in body ? Number(body.govtFee) : current.govtFee;
      const nextAdditionalCharges =
        'additionalCharges' in body ? Number(body.additionalCharges) : current.additionalCharges;

      if (
        !Number.isFinite(nextServiceCharge) ||
        nextServiceCharge < 0 ||
        !Number.isFinite(nextServiceCost) ||
        nextServiceCost < 0 ||
        !Number.isFinite(nextGovtFee) ||
        nextGovtFee < 0 ||
        !Number.isFinite(nextAdditionalCharges) ||
        nextAdditionalCharges < 0
      ) {
        failHttp('Rate fields must be valid numbers >= 0.', 422);
      }

      const totalCustomerCharge = round2(nextServiceCharge + nextGovtFee + nextAdditionalCharges);
      const profitAmount = round2(nextServiceCharge + nextAdditionalCharges - nextServiceCost);

      let categoryId = current.categoryId;
      let categoryName = current.categoryName;
      if (body.categoryId !== undefined && Number(body.categoryId) !== current.categoryId) {
        const cats = await listCollectionScoped('serviceCategories');
        const matchedCat = cats.find((c) => Number(c.id) === Number(body.categoryId));
        if (!matchedCat) failHttp('Selected Category not found.', 422);
        categoryId = Number(matchedCat.id);
        categoryName = String(matchedCat.name || 'General');
      }

      let subcategoryId = current.subcategoryId;
      let subcategoryName = current.subcategoryName;
      if ('subcategoryId' in body) {
        if (body.subcategoryId === null || body.subcategoryId === '') {
          subcategoryId = undefined;
          subcategoryName = undefined;
        } else {
          const subs = await listCollectionScoped('serviceSubcategories');
          const matchedSub = subs.find(
            (sc) => Number(sc.id) === Number(body.subcategoryId) && Number(sc.categoryId) === categoryId
          );
          if (!matchedSub) {
            failHttp('Selected Subcategory does not belong to the chosen Category.', 422);
          }
          subcategoryId = Number(matchedSub.id);
          subcategoryName = String(matchedSub.name || '');
        }
      }

      const instructions =
        'serviceInstructions' in body
          ? str(body.serviceInstructions, 2000)
          : 'termsAndConditions' in body
            ? str(body.termsAndConditions, 2000)
            : current.serviceInstructions || current.termsAndConditions;

      const nextStatus = 'status' in body ? str(body.status, 40) : current.status;
      const nextAvailability =
        'availability' in body
          ? str(body.availability, 32)
          : nextStatus === 'Active'
            ? 'Available'
            : 'Unavailable';

      const updateData: Record<string, unknown> = {
        name: 'name' in body ? str(body.name, 160) : current.name,
        categoryId,
        categoryName,
        subcategoryId: subcategoryId ?? null,
        subcategoryName: subcategoryName ?? null,
        description: 'description' in body ? str(body.description, 600) : current.description,
        serviceCharge: round2(nextServiceCharge),
        serviceCost: round2(nextServiceCost),
        govtFee: round2(nextGovtFee),
        additionalCharges: round2(nextAdditionalCharges),
        totalCustomerCharge,
        customerCharge: totalCustomerCharge,
        profitAmount,
        status: nextStatus,
        availability: nextAvailability,
        serviceInstructions: instructions,
        termsAndConditions: instructions,
        displayOrder:
          body.displayOrder !== undefined && Number.isFinite(Number(body.displayOrder))
            ? Number(body.displayOrder)
            : current.displayOrder ?? current.id,
        ...(body.sla ? { sla: body.sla } : {}),
        ...(Array.isArray(body.requiredDocuments)
          ? { requiredDocuments: body.requiredDocuments.slice(0, 30) }
          : {}),
        ...(Array.isArray(body.automationRules)
          ? { automationRules: body.automationRules.slice(0, 20) }
          : {}),
        updatedBy: currentProfile.userId,
        updatedAt: serverTimestamp(),
      };

      await updateDoc(found.ref, updateData);
      const updated = await getDoc(found.ref);
      return okEnvelope(normalizeServiceDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `services/${serviceIdParam}`);
    }
  }

  const serviceDeleteMatch = pathname.match(/^\/api\/erp\/services\/([^/]+)$/);
  if (serviceDeleteMatch && method === 'DELETE') {
    if (!isAdminOrManagerUser) failHttp('Only Admin or Manager can delete services.', 403);
    const serviceIdParam = decodeURIComponent(serviceDeleteMatch[1]);
    try {
      const found = await resolveServiceDocRef(serviceIdParam);
      if (!found) failHttp('Service not found.', 404);
      const existingData = found.snap.data() as Record<string, unknown>;
      await deleteDoc(found.ref);
      return okEnvelope({
        deleted: true,
        serviceId: String(existingData.serviceId || found.snap.id),
        serviceCode: String(existingData.serviceCode || ''),
      }) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.DELETE, `services/${serviceIdParam}`);
    }
  }

  const serviceFormVersionMatch = pathname.match(/^\/api\/erp\/services\/([^/]+)\/form-versions$/);
  if (serviceFormVersionMatch && method === 'POST') {
    if (!isAdminOrManagerUser) failHttp('Only Admin or Manager can publish service form versions.', 403);
    const serviceIdParam = decodeURIComponent(serviceFormVersionMatch[1]);
    try {
      const found = await resolveServiceDocRef(serviceIdParam);
      if (!found) failHttp('Service not found.', 404);
      const current = normalizeServiceDoc(found.snap.data() as Record<string, unknown>);
      const fields = Array.isArray(body.fields) ? body.fields : [];
      if (fields.length === 0) {
        failHttp('At least one form field definition is required.', 422);
      }
      const nextVersion = current.currentFormVersion + 1;
      const nextVersions = [
        {
          versionNo: nextVersion,
          publishedAt: new Date().toISOString(),
          publishedBy: currentProfile.userId,
          status: 'published',
          fields,
        },
        ...current.formVersions,
      ].slice(0, 20);
      await updateDoc(found.ref, {
        currentFormVersion: nextVersion,
        formVersions: nextVersions,
        updatedBy: currentProfile.userId,
        updatedAt: serverTimestamp(),
      });
      const updated = await getDoc(found.ref);
      return okEnvelope(normalizeServiceDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `services/${serviceIdParam}`);
    }
  }

  if (pathname === '/api/service-rates' && method === 'GET') {
    const raw = await listCollectionScoped('services');
    const rates: ServiceRateItem[] = raw
      .map(normalizeServiceDoc)
      .filter((s) => !LEGACY_MOCK_SERVICE_IDS.includes(s.serviceId) && !s.deletedAt)
      .sort((a, b) => (a.displayOrder ?? a.id) - (b.displayOrder ?? b.id) || a.id - b.id)
      .map((s) => ({
        id: s.id,
        serviceCode: s.serviceCode,
        serviceName: s.name,
        category: s.categoryName,
        customerCharge: s.totalCustomerCharge,
        serviceCost: s.serviceCost,
        profitAmount: s.profitAmount,
        currentVersion: s.currentFormVersion,
        effectiveDate: (s.createdAt || new Date().toISOString()).slice(0, 10),
        status: s.status === 'Active' ? 'active' : 'inactive',
        versions: [],
      }));
    return okEnvelope({ rates, completedSnapshots: [] }) as ApiResponseEnvelope<T>;
  }

  // =========================================================================
  // APPLICATIONS WORKFLOW (LIVE FIRESTORE)
  // =========================================================================
  if (pathname === '/api/erp/applications' && method === 'GET') {
    const qText = (searchParams.get('q') || '').trim().toLowerCase();
    const statusFilter = searchParams.get('status') || '';
    const customerFilter = searchParams.get('customerId') || '';
    const serviceFilter = searchParams.get('serviceId') || '';
    const includeArchived = searchParams.get('includeArchived') === 'true';

    const raw = await listCollectionScoped('applications');
    const list = raw
      .map(normalizeApplicationDoc)
      .filter((a) => (includeArchived ? true : !a.archivedAt))
      .filter((a) => (!statusFilter ? true : a.status === statusFilter))
      .filter((a) => (!customerFilter ? true : a.customerId === customerFilter))
      .filter((a) => (!serviceFilter ? true : a.serviceId === serviceFilter))
      .filter((a) => {
        if (!qText) return true;
        return (
          a.applicationNo.toLowerCase().includes(qText) ||
          a.customerSnapshot.fullName.toLowerCase().includes(qText) ||
          a.serviceSnapshot.name.toLowerCase().includes(qText)
        );
      })
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    return okEnvelope(list) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/erp/applications/check-duplicate' && method === 'POST') {
    const cId = str(body.customerId, 64);
    const sId = str(body.serviceId, 64);
    const apps = (await listCollectionScoped('applications')).map(normalizeApplicationDoc);
    const matches = apps
      .filter((a) => a.customerId === cId && a.serviceId === sId && !a.archivedAt)
      .map((a) => ({ applicationNo: a.applicationNo, status: a.status, createdAt: a.createdAt }));
    return okEnvelope({ hasDuplicate: matches.length > 0, matches }) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/erp/applications' && method === 'POST') {
    const customerId = str(body.customerId, 64);
    const serviceId = str(body.serviceId, 64);
    if (!customerId || !serviceId) {
      failHttp('Both customerId and serviceId are required.', 422);
    }

    const [custSnap, svcSnap] = await Promise.all([
      getDoc(doc(db, 'customers', customerId)),
      getDoc(doc(db, 'services', serviceId)),
    ]);
    if (!custSnap.exists()) failHttp(`Customer ${customerId} not found in Firestore.`, 404);
    if (!svcSnap.exists()) failHttp(`Service ${serviceId} not found in Firestore.`, 404);

    const cust = normalizeCustomerDoc(custSnap.data() as Record<string, unknown>);
    const svc = normalizeServiceDoc(svcSnap.data() as Record<string, unknown>);
    const seq = await allocateSequence('APP');
    const applicationNo = `APP-2026-27-${String(seq).padStart(6, '0')}`;
    const expectedDays = svc.sla?.expectedDays || 3;
    const expectedCompletionDate = new Date(Date.now() + expectedDays * 86_400_000)
      .toISOString()
      .slice(0, 10);
    const nowIso = new Date().toISOString();

    const initialStatus = body.saveAsDraft ? 'Draft' : 'Submitted';
    const appDocPayload: Record<string, unknown> = {
      id: seq,
      applicationNo,
      financialYear: '2026-27',
      customerId,
      customerSnapshot: {
        customerId: cust.customerId,
        fullName: cust.fullName,
        fatherOrHusbandName: cust.fatherOrHusbandName,
        dob: cust.dob,
        gender: cust.gender,
        mobile: cust.mobile,
        whatsapp: cust.whatsapp,
        village: cust.village,
        presentAddress: cust.presentAddress,
      },
      serviceId,
      serviceSnapshot: {
        serviceId: svc.serviceId,
        serviceCode: svc.serviceCode,
        name: svc.name,
        categoryName: svc.categoryName,
        appliedFormVersion: svc.currentFormVersion,
        formFieldsSnapshot: svc.formVersions?.[0]?.fields || [],
        requiredDocsSnapshot: svc.requiredDocuments || [],
        customerChargeSnapshot: svc.customerCharge,
        serviceCostSnapshot: svc.serviceCost,
        profitSnapshot: svc.profitAmount,
        termsSnapshot: svc.termsAndConditions,
      },
      formData: (body.formData as Record<string, unknown>) || {},
      status: initialStatus,
      assignedStaffId: body.assignedStaffId ? str(body.assignedStaffId, 64) : currentProfile.userId,
      assignedCounterCode: body.assignedCounterCode ? str(body.assignedCounterCode, 40) : 'CNT-01',
      submissionDate: body.saveAsDraft ? null : nowIso,
      expectedCompletionDate,
      actualCompletionDate: null,
      references: [],
      statusHistory: [
        {
          id: 1,
          previousStatus: null,
          newStatus: initialStatus,
          changedBy: currentProfile.userId,
          changedByRole: currentProfile.role,
          remarks: 'Application created',
          reason: '',
          changedAt: nowIso,
        },
      ],
      assignmentHistory: [],
      checklistSummary: {
        requiredDocuments: svc.requiredDocuments?.filter((d) => d.required).length || 0,
        optionalDocuments: svc.requiredDocuments?.filter((d) => !d.required).length || 0,
        uploadedDocuments: 0,
        uploadedMandatoryCount: 0,
        verifiedDocuments: 0,
        pendingVerification: 0,
        rejectedDocuments: 0,
        missingCount: 0,
        missingRequiredLabels: [],
        isSubmissionReady: true,
      },
      slaStatus: { label: 'On Track', badge: 'success' },
      documents: [],
      financialSummary: {
        serviceCharge: svc.customerCharge,
        serviceCost: svc.serviceCost,
        profitAmount: svc.profitAmount,
        totalPaid: 0,
        totalRefunded: 0,
        netCollected: 0,
        balanceDue: svc.customerCharge,
        paymentStatus: 'Unpaid',
      },
      payments: [],
      refunds: [],
      followUps: [],
      notes: [],
      delivery: null,
      cancellations: [],
      reassignments: [],
      notifications: [],
      activities: [
        {
          id: 1,
          actorUserId: currentProfile.userId,
          action: 'CREATED',
          applicationNo,
          newValue: initialStatus,
          createdAt: nowIso,
        },
      ],
      archivedAt: null,
      createdByUid: uid,
      createdBy: currentProfile.userId,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };

    try {
      await setDoc(doc(db, 'applications', applicationNo), appDocPayload);
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `applications/${applicationNo}`);
    }

    const saved = await getDoc(doc(db, 'applications', applicationNo));
    return okEnvelope(normalizeApplicationDoc(saved.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
  }

  const appDetailMatch = pathname.match(/^\/api\/erp\/applications\/([^/]+)$/);
  if (appDetailMatch && method === 'GET') {
    const appNo = decodeURIComponent(appDetailMatch[1]);
    try {
      const aSnap = await getDoc(doc(db, 'applications', appNo));
      if (!aSnap.exists()) failHttp('Application not found.', 404);
      const application = normalizeApplicationDoc(aSnap.data() as Record<string, unknown>);
      const cSnap = await getDoc(doc(db, 'customers', application.customerId));
      const customer = cSnap.exists()
        ? normalizeCustomerDoc(cSnap.data() as Record<string, unknown>)
        : null;
      return okEnvelope({ application, customer }) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.GET, `applications/${appNo}`);
    }
  }

  const appStatusMatch = pathname.match(/^\/api\/erp\/applications\/([^/]+)\/status$/);
  if (appStatusMatch && method === 'POST') {
    const appNo = decodeURIComponent(appStatusMatch[1]);
    const aRef = doc(db, 'applications', appNo);
    try {
      const snap = await getDoc(aRef);
      if (!snap.exists()) failHttp('Application not found.', 404);
      const app = normalizeApplicationDoc(snap.data() as Record<string, unknown>);
      const nextStatus = str(body.nextStatus, 40) as ErpApplicationItem['status'];
      const nowIso = new Date().toISOString();
      const nextHistory = [
        ...app.statusHistory,
        {
          id: Date.now(),
          previousStatus: app.status,
          newStatus: nextStatus,
          changedBy: currentProfile.userId,
          changedByRole: currentProfile.role,
          remarks: str(body.remarks, 200),
          reason: str(body.reason, 200),
          changedAt: nowIso,
        },
      ].slice(-50);
      await updateDoc(aRef, {
        status: nextStatus,
        statusHistory: nextHistory,
        ...(nextStatus === 'Completed' ? { actualCompletionDate: nowIso } : {}),
        updatedAt: serverTimestamp(),
      });
      const updated = await getDoc(aRef);
      return okEnvelope(normalizeApplicationDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `applications/${appNo}`);
    }
  }

  const appNotesMatch = pathname.match(/^\/api\/erp\/applications\/([^/]+)\/notes$/);
  if (appNotesMatch && method === 'POST') {
    const appNo = decodeURIComponent(appNotesMatch[1]);
    const aRef = doc(db, 'applications', appNo);
    try {
      const snap = await getDoc(aRef);
      if (!snap.exists()) failHttp('Application not found.', 404);
      const app = normalizeApplicationDoc(snap.data() as Record<string, unknown>);
      const nextNotes = [
        {
          id: Date.now(),
          noteType: body.noteType === 'CUSTOMER_REMARK' ? 'CUSTOMER_REMARK' : 'INTERNAL',
          content: str(body.content, 400),
          authorUserId: currentProfile.userId,
          createdAt: new Date().toISOString(),
        },
        ...app.notes,
      ].slice(0, 100);
      await updateDoc(aRef, { notes: nextNotes, updatedAt: serverTimestamp() });
      const updated = await getDoc(aRef);
      return okEnvelope(normalizeApplicationDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `applications/${appNo}`);
    }
  }

  const appFollowUpMatch = pathname.match(/^\/api\/erp\/applications\/([^/]+)\/follow-ups$/);
  if (appFollowUpMatch && method === 'POST') {
    const appNo = decodeURIComponent(appFollowUpMatch[1]);
    const aRef = doc(db, 'applications', appNo);
    try {
      const snap = await getDoc(aRef);
      if (!snap.exists()) failHttp('Application not found.', 404);
      const app = normalizeApplicationDoc(snap.data() as Record<string, unknown>);
      const nextFollowUps = [
        {
          id: Date.now(),
          title: str(body.title || 'Follow-Up', 120),
          dueDate: str(body.dueDate, 32),
          assignedTo: str(body.assignedTo || currentProfile.userId, 64),
          status: 'Open',
          notes: str(body.notes, 300),
          createdAt: new Date().toISOString(),
        },
        ...app.followUps,
      ].slice(0, 50);
      await updateDoc(aRef, { followUps: nextFollowUps, updatedAt: serverTimestamp() });
      const updated = await getDoc(aRef);
      return okEnvelope(normalizeApplicationDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `applications/${appNo}`);
    }
  }

  const appDeliveryMatch = pathname.match(/^\/api\/erp\/applications\/([^/]+)\/delivery$/);
  if (appDeliveryMatch && method === 'POST') {
    const appNo = decodeURIComponent(appDeliveryMatch[1]);
    const aRef = doc(db, 'applications', appNo);
    try {
      const snap = await getDoc(aRef);
      if (!snap.exists()) failHttp('Application not found.', 404);
      const delivery = {
        deliveryMode: str(body.deliveryMode || 'Counter Pickup', 48),
        receiverName: str(body.receiverName, 120),
        receiverMobile: str(body.receiverMobile, 24),
        remarks: str(body.remarks, 300),
        deliveredBy: currentProfile.userId,
        deliveredAt: new Date().toISOString(),
      };
      await updateDoc(aRef, { delivery, updatedAt: serverTimestamp() });
      const updated = await getDoc(aRef);
      return okEnvelope(normalizeApplicationDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `applications/${appNo}`);
    }
  }

  const appAssignMatch = pathname.match(/^\/api\/erp\/applications\/([^/]+)\/assign$/);
  if (appAssignMatch && method === 'POST') {
    const appNo = decodeURIComponent(appAssignMatch[1]);
    const aRef = doc(db, 'applications', appNo);
    try {
      const snap = await getDoc(aRef);
      if (!snap.exists()) failHttp('Application not found.', 404);
      const app = normalizeApplicationDoc(snap.data() as Record<string, unknown>);
      const nextStaff =
        body.action === 'CLAIM'
          ? currentProfile.userId
          : str(body.assignedStaffId || currentProfile.userId, 64);
      const nextHistory = [
        ...app.assignmentHistory,
        {
          id: Date.now(),
          fromStaffId: app.assignedStaffId,
          toStaffId: nextStaff,
          changedBy: currentProfile.userId,
          reason: str(body.reason || 'Assigned via workspace', 200),
          changedAt: new Date().toISOString(),
        },
      ].slice(-50);
      await updateDoc(aRef, {
        assignedStaffId: nextStaff,
        assignmentHistory: nextHistory,
        updatedAt: serverTimestamp(),
      });
      const updated = await getDoc(aRef);
      return okEnvelope(normalizeApplicationDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `applications/${appNo}`);
    }
  }

  const appFormMatch = pathname.match(/^\/api\/erp\/applications\/([^/]+)\/form-data$/);
  if (appFormMatch && method === 'PUT') {
    const appNo = decodeURIComponent(appFormMatch[1]);
    const aRef = doc(db, 'applications', appNo);
    try {
      const snap = await getDoc(aRef);
      if (!snap.exists()) failHttp('Application not found.', 404);
      await updateDoc(aRef, {
        formData: (body.formData as Record<string, unknown>) || {},
        updatedAt: serverTimestamp(),
      });
      const updated = await getDoc(aRef);
      return okEnvelope(normalizeApplicationDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `applications/${appNo}`);
    }
  }

  const appRefMatch = pathname.match(/^\/api\/erp\/applications\/([^/]+)\/references$/);
  if (appRefMatch && method === 'POST') {
    const appNo = decodeURIComponent(appRefMatch[1]);
    const aRef = doc(db, 'applications', appNo);
    try {
      const snap = await getDoc(aRef);
      if (!snap.exists()) failHttp('Application not found.', 404);
      const app = normalizeApplicationDoc(snap.data() as Record<string, unknown>);
      const fieldKey = str(body.fieldKey, 64);
      const filtered = app.references.filter((r) => r.fieldKey !== fieldKey);
      const nextRefs = [
        ...filtered,
        {
          id: Date.now(),
          fieldKey,
          label: fieldKey,
          value: str(body.value, 160),
          enteredBy: currentProfile.userId,
          updatedAt: new Date().toISOString(),
        },
      ].slice(0, 30);
      await updateDoc(aRef, { references: nextRefs, updatedAt: serverTimestamp() });
      const updated = await getDoc(aRef);
      return okEnvelope(normalizeApplicationDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `applications/${appNo}`);
    }
  }

  // =========================================================================
  // PAYMENTS, EXPENSES & REFUNDS (LIVE FIRESTORE)
  // =========================================================================
  if (pathname === '/api/erp/payments' && method === 'GET') {
    const [pRaw, rRaw, eRaw] = await Promise.all([
      listCollectionScoped('payments'),
      listCollectionScoped('refunds'),
      listCollectionScoped('expenses'),
    ]);
    return okEnvelope({
      payments: pRaw.map(normalizePaymentDoc),
      refunds: rRaw.map(normalizeRefundDoc),
      expenses: eRaw.map(normalizeExpenseDoc),
    }) as ApiResponseEnvelope<T>;
  }

  const paymentVerifyMatch = pathname.match(/^\/api\/erp\/payments\/([^/]+)\/verify$/);
  if (paymentVerifyMatch && method === 'POST') {
    const transactionId = decodeURIComponent(paymentVerifyMatch[1]);
    const pRef = doc(db, 'payments', transactionId);
    try {
      const snap = await getDoc(pRef);
      if (!snap.exists()) failHttp('Payment not found.', 404);
      const verificationStatus = body.decision === 'Rejected' ? 'Rejected' : 'Confirmed';
      await updateDoc(pRef, {
        verificationStatus,
        verifiedBy: currentProfile.userId,
        updatedAt: serverTimestamp(),
      });
      const updated = await getDoc(pRef);
      return okEnvelope(normalizePaymentDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `payments/${transactionId}`);
    }
  }

  if (pathname === '/api/erp/refunds' && method === 'POST') {
    const applicationNo = str(body.applicationNo, 64);
    const refundAmount = Number(body.refundAmount || 0);
    if (!applicationNo || refundAmount <= 0) {
      failHttp('Application number and positive refund amount are required.', 422);
    }
    const aSnap = await getDoc(doc(db, 'applications', applicationNo));
    if (!aSnap.exists()) failHttp(`Application ${applicationNo} not found.`, 404);
    const app = normalizeApplicationDoc(aSnap.data() as Record<string, unknown>);
    const seq = await allocateSequence('RFD');
    const refundId = `RFD-2026-${String(seq).padStart(4, '0')}`;
    const refundMethodRaw = str(body.refundMethod || 'Cash', 32);
    try {
      await setDoc(doc(db, 'refunds', refundId), {
        id: seq,
        refundId,
        applicationNo,
        customerId: app.customerId,
        originalTransactionId: str(body.originalTransactionId, 64),
        refundType: str(body.refundType || 'Partial', 20),
        refundAmount,
        refundMethod: refundMethodRaw,
        refundReason: str(body.refundReason, 300),
        status: 'Pending',
        requestedBy: currentProfile.userId,
        approvedBy: null,
        processedBy: null,
        processedAt: null,
        createdByUid: uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
      const saved = await getDoc(doc(db, 'refunds', refundId));
      return okEnvelope(normalizeRefundDoc(saved.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `refunds/${refundId}`);
    }
  }

  const refundProcessMatch = pathname.match(/^\/api\/erp\/refunds\/([^/]+)\/process$/);
  if (refundProcessMatch && method === 'POST') {
    const refundId = decodeURIComponent(refundProcessMatch[1]);
    const rRef = doc(db, 'refunds', refundId);
    try {
      const snap = await getDoc(rRef);
      if (!snap.exists()) failHttp('Refund not found.', 404);
      const status = body.decision === 'Rejected' ? 'Rejected' : 'Processed';
      await updateDoc(rRef, {
        status,
        approvedBy: currentProfile.userId,
        processedBy: currentProfile.userId,
        processedAt: new Date().toISOString(),
        updatedAt: serverTimestamp(),
      });
      const updated = await getDoc(rRef);
      return okEnvelope(normalizeRefundDoc(updated.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      if ((err as { status?: number }).status) throw err;
      handleFirestoreError(err, OperationType.UPDATE, `refunds/${refundId}`);
    }
  }

  if (pathname === '/api/erp/payments' && method === 'POST') {
    const applicationNo = str(body.applicationNo, 64);
    const amount = Number(body.amount || 0);
    if (!applicationNo || amount <= 0) {
      failHttp('Application number and positive payment amount are required.', 422);
    }

    const aRef = doc(db, 'applications', applicationNo);
    const aSnap = await getDoc(aRef);
    if (!aSnap.exists()) failHttp(`Application ${applicationNo} not found.`, 404);
    const app = normalizeApplicationDoc(aSnap.data() as Record<string, unknown>);

    const seq = await allocateSequence('TXN');
    const transactionId = `TXN-2026-${String(seq).padStart(5, '0')}`;
    const receiptNo = `REC-2026-27-${String(seq).padStart(6, '0')}`;
    const paymentMethodRaw = str(body.paymentMethod, 32);
    const paymentMethod = (
      ['Cash', 'UPI', 'Card', 'Bank Transfer', 'Other'].includes(paymentMethodRaw)
        ? paymentMethodRaw
        : 'Cash'
    ) as ErpPaymentItem['paymentMethod'];

    const paymentPayload: Record<string, unknown> = {
      id: seq,
      transactionId,
      receiptNo,
      applicationNo,
      customerId: app.customerId,
      customerName: app.customerSnapshot.fullName,
      serviceId: app.serviceId,
      serviceName: app.serviceSnapshot.name,
      counterCode: str(body.counterCode || 'CNT-01', 40),
      collectedBy: currentProfile.userId,
      paymentType: str(body.paymentType || 'Full', 20),
      paymentMethod,
      ...(body.upiReference ? { upiReference: str(body.upiReference, 80) } : {}),
      amount,
      verificationStatus: 'Confirmed',
      verifiedBy: currentProfile.userId,
      recordedAt: new Date().toISOString(),
      notes: str(body.notes, 400),
      createdByUid: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };

    try {
      await setDoc(doc(db, 'payments', transactionId), paymentPayload);
      const nextTotalPaid = app.financialSummary.totalPaid + amount;
      const nextBalance = Math.max(0, app.financialSummary.serviceCharge - nextTotalPaid);
      await updateDoc(aRef, {
        financialSummary: {
          ...app.financialSummary,
          totalPaid: nextTotalPaid,
          netCollected: Math.max(0, nextTotalPaid - app.financialSummary.totalRefunded),
          balanceDue: nextBalance,
          paymentStatus: nextBalance === 0 ? 'Paid' : 'Partial',
        },
        updatedAt: serverTimestamp(),
      });
      const saved = await getDoc(doc(db, 'payments', transactionId));
      return okEnvelope(normalizePaymentDoc(saved.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `payments/${transactionId}`);
    }
  }

  if (pathname === '/api/erp/expenses' && method === 'POST') {
    const category = str(body.category, 80);
    const amount = Number(body.amount || 0);
    if (!category || amount <= 0) {
      failHttp('Expense category and positive amount are required.', 422);
    }
    const seq = await allocateSequence('VCH');
    const voucherNo = `VCH-2026-${String(seq).padStart(5, '0')}`;
    try {
      await setDoc(doc(db, 'expenses', voucherNo), {
        id: seq,
        voucherNo,
        category,
        description: str(body.description, 300),
        counterCode: str(body.counterCode || 'CNT-01', 40),
        amount,
        expenseDate: str(body.expenseDate || new Date().toISOString().slice(0, 10), 32),
        recordedBy: currentProfile.userId,
        status: 'Approved',
        createdByUid: uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
      const saved = await getDoc(doc(db, 'expenses', voucherNo));
      return okEnvelope(normalizeExpenseDoc(saved.data() as Record<string, unknown>)) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `expenses/${voucherNo}`);
    }
  }

  // =========================================================================
  // DAILY CASH, NOTIFICATIONS, USERS, SECURITY LOGS
  // =========================================================================
  if (pathname === '/api/daily-cash' && method === 'GET') {
    const raw = await listCollectionScoped('dailyCashClosings');
    const list: DailyCashClosingRecord[] = raw.map((r, idx) => ({
      id: Number(r.id || idx + 1),
      closingCode: String(r.closingCode || ''),
      branchId: Number(r.branchId || 1),
      counterCode: String(r.counterCode || 'CNT-01'),
      closingDate: String(r.closingDate || ''),
      openingCash: Number(r.openingCash || 0),
      cashReceived: Number(r.cashReceived || 0),
      cashExpenses: Number(r.cashExpenses || 0),
      expectedCash: Number(r.expectedCash || 0),
      actualCashCount: Number(r.actualCashCount || 0),
      cashDifference: Number(r.cashDifference || 0),
      differenceReason: String(r.differenceReason || ''),
      submittedBy: String(r.submittedBy || ''),
      approvedBy: r.approvedBy ? String(r.approvedBy) : null,
      approvalStatus: (r.approvalStatus as DailyCashClosingRecord['approvalStatus']) || 'Approved',
      createdAt: timestampToIso(r.createdAt),
      correctionAudit: Array.isArray(r.correctionAudit) ? r.correctionAudit : [],
    }));
    return okEnvelope(list) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/erp/notifications/send' && method === 'POST') {
    const seq = await allocateSequence('NTF');
    const notificationId = `NTF-${Date.now()}-${seq}`;
    const channelRaw = str(body.channel || 'DASHBOARD', 24);
    const channel = (
      ['DASHBOARD', 'SMS', 'EMAIL_SMTP', 'WHATSAPP'].includes(channelRaw) ? channelRaw : 'DASHBOARD'
    ) as ErpNotificationDispatchItem['channel'];
    const payload = {
      id: seq,
      notificationId,
      ...(body.applicationNo ? { applicationNo: str(body.applicationNo, 64) } : {}),
      customerId: str(body.customerId || 'GENERAL', 64),
      channel,
      eventKey: str(body.eventKey || 'MANUAL_ALERT', 64),
      recipient: str(body.recipient || 'Counter Desk', 160),
      messagePreview: str(body.messagePreview || body.message || 'Notification dispatched', 500),
      consentChecked: Boolean(body.consentChecked ?? true),
      consentGranted: Boolean(body.consentGranted ?? true),
      status: 'Delivered (Internal)',
      statusReason: 'Recorded in Firestore notifications log',
      createdBy: currentProfile.userId,
      createdByUid: uid,
      createdAt: serverTimestamp(),
    };
    try {
      await setDoc(doc(db, 'notifications', notificationId), payload);
      return okEnvelope({
        ...payload,
        createdAt: new Date().toISOString(),
      }) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `notifications/${notificationId}`);
    }
  }

  if (pathname === '/api/erp/reports/summary' && method === 'GET') {
    const [appsRaw, paymentsRaw, refundsRaw] = await Promise.all([
      listCollectionScoped('applications'),
      listCollectionScoped('payments'),
      listCollectionScoped('refunds'),
    ]);
    const apps = appsRaw.map(normalizeApplicationDoc).filter((a) => !a.archivedAt);
    const payments = paymentsRaw.map(normalizePaymentDoc);
    const refunds = refundsRaw.map(normalizeRefundDoc);

    const statusSummary: Record<string, number> = {};
    const serviceAgg = new Map<string, { serviceId: string; serviceName: string; count: number; revenue: number; profit: number }>();
    const staffAgg = new Map<string, { staffId: string; total: number; completed: number; pending: number; overdue: number }>();

    for (const a of apps) {
      statusSummary[a.status] = (statusSummary[a.status] || 0) + 1;
      const sKey = a.serviceId;
      const curSvc = serviceAgg.get(sKey) || {
        serviceId: a.serviceId,
        serviceName: a.serviceSnapshot.name,
        count: 0,
        revenue: 0,
        profit: 0,
      };
      curSvc.count += 1;
      curSvc.revenue += a.financialSummary.serviceCharge;
      curSvc.profit += a.financialSummary.profitAmount;
      serviceAgg.set(sKey, curSvc);

      const stKey = a.assignedStaffId || 'Unassigned';
      const curSt = staffAgg.get(stKey) || {
        staffId: stKey,
        total: 0,
        completed: 0,
        pending: 0,
        overdue: 0,
      };
      curSt.total += 1;
      if (a.status === 'Completed' || a.status === 'Approved') curSt.completed += 1;
      else curSt.pending += 1;
      staffAgg.set(stKey, curSt);
    }

    return okEnvelope({
      totalApplications: apps.length,
      statusSummary,
      staffWorkload: Array.from(staffAgg.values()),
      serviceSummary: Array.from(serviceAgg.values()),
      pendingDocumentsApps: apps.filter((a) => a.checklistSummary.missingCount > 0),
      overdueSlaApps: [],
      followUps: apps.flatMap((a) => a.followUps),
      deliveries: apps.map((a) => a.delivery).filter(Boolean),
      cancellations: apps.flatMap((a) => a.cancellations),
      refunds,
      exportLogs: [],
      activities: apps.flatMap((a) => a.activities).slice(0, 50),
      totalConfirmedPayments: payments.filter((p) => p.verificationStatus === 'Confirmed').length,
    }) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/erp/reports/export-log' && method === 'POST') {
    await writeSecurityLog(
      'REPORT_EXPORTED',
      currentProfile.userId,
      `Exported ${str(body.reportName, 120)} (${str(body.format, 16)}, ${Number(body.rowCount || 0)} rows)`
    );
    return okEnvelope({ logged: true }) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/erp/notifications' && method === 'GET') {
    const raw = await listCollectionScoped('notifications');
    const list: ErpNotificationDispatchItem[] = raw.map((r, idx) => ({
      id: Number(r.id || idx + 1),
      applicationNo: r.applicationNo ? String(r.applicationNo) : undefined,
      customerId: String(r.customerId || ''),
      channel: (r.channel as ErpNotificationDispatchItem['channel']) || 'DASHBOARD',
      eventKey: String(r.eventKey || ''),
      recipient: String(r.recipient || ''),
      messagePreview: String(r.messagePreview || ''),
      consentChecked: Boolean(r.consentChecked),
      consentGranted: Boolean(r.consentGranted),
      status: (r.status as ErpNotificationDispatchItem['status']) || 'Delivered (Internal)',
      statusReason: String(r.statusReason || ''),
      createdBy: String(r.createdBy || ''),
      createdAt: timestampToIso(r.createdAt),
    }));
    return okEnvelope(list) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/users/id-prefix-preview' && method === 'GET') {
    const fy = resolveFinancialYearCodeIST();
    const mm = getIstMonthCode();
    return okEnvelope({
      prefix: getCurrentUserIdPrefix(),
      financialYearCode: fy,
      monthCode: mm,
    }) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/departments' && method === 'GET') {
    const defaults = [
      { code: 'DEPT-CSC', name: 'CSC Digital Service Center' },
      { code: 'DEPT-OPS', name: 'Front Desk & Operations' },
      { code: 'DEPT-FIN', name: 'Accounts & Finance Engine' },
      { code: 'DEPT-LEGAL', name: 'Documentation & Compliance' },
    ];
    try {
      const snap = await getDocs(collection(db, 'departments'));
      if (snap.empty) return okEnvelope(defaults) as ApiResponseEnvelope<T>;
      const list = snap.docs.map((d) => {
        const data = d.data();
        return {
          code: String(data.departmentCode || d.id),
          name: String(data.name || d.id),
        };
      });
      return okEnvelope(list) as ApiResponseEnvelope<T>;
    } catch {
      return okEnvelope(defaults) as ApiResponseEnvelope<T>;
    }
  }

  if (pathname === '/api/users' && method === 'GET') {
    if (!isBootAdmin && currentProfile.role !== 'ADMIN') {
      return okEnvelope([
        {
          ...currentProfile,
          permissions: buildPermissionsForRole(currentProfile.role),
        },
      ]) as ApiResponseEnvelope<T>;
    }
    let raw: Record<string, unknown>[] = [];
    try {
      const snap = await getDocs(collection(db, 'users'));
      raw = snap.docs.map((d) => d.data() as Record<string, unknown>);
    } catch {
      return okEnvelope([
        {
          ...currentProfile,
          permissions: buildPermissionsForRole(currentProfile.role),
        },
      ]) as ApiResponseEnvelope<T>;
    }
    const users = raw.map((u, idx) => {
      const role = (u.role as RoleName) || 'STAFF';
      const fullName = String(u.fullName || 'User');
      return {
        id: idx + 1,
        userId: String(u.userId || ''),
        fullName,
        email: '',
        role,
        mobile: '',
        address: '',
        avatarInitials: fullName
          .split(' ')
          .map((p) => p[0])
          .slice(0, 2)
          .join('')
          .toUpperCase(),
        branch: String(u.branch || 'Main Service Center'),
        departmentCode: String(u.departmentCode || 'DEPT-CSC'),
        designation: String(u.designation || ''),
        isMasterAdmin: Boolean(u.isMasterAdmin),
        status: String(u.status || 'ACTIVE'),
        mobileVerified: Boolean(u.mobileVerified),
        emailVerified: Boolean(u.emailVerified),
        createdAt: timestampToIso(u.createdAt),
        permissions: buildPermissionsForRole(role),
      };
    });
    return okEnvelope(users) as ApiResponseEnvelope<T>;
  }

  if (pathname === '/api/users' && method === 'POST') {
    const isAdminUser = isBootAdmin || currentProfile.role === 'ADMIN';
    if (!isAdminUser) {
      failHttp('Only ADMIN can provision user accounts directly in Firebase mode.', 403);
    }
    const fullName = str(body.fullName, 120);
    const mobile = str(body.mobile, 24);
    const address = str(body.address, 300);
    const email = str(body.email, 160);
    const branch = str(body.branch || 'Main Service Center', 120);
    const designation = str(body.designation, 120);
    const departmentCode = str(body.departmentCode || 'DEPT-CSC', 40);
    const joiningDate = str(body.joiningDate || new Date().toISOString().slice(0, 10), 32);
    const roleRaw = str(body.role || 'STAFF', 24).toUpperCase();
    const role = (['ADMIN', 'MANAGER', 'STAFF', 'AUDITOR', 'CUSTOMER'].includes(roleRaw) ? roleRaw : 'STAFF') as RoleName;
    const password = String(body.password || '');
    const confirmPassword = String(body.confirmPassword || '');

    if (fullName.length < 2) failHttp('Full name must be at least 2 characters.', 422);
    if (mobile.length < 10) failHttp('Valid 10-digit mobile number is required.', 422);
    if (address.length < 3) failHttp('Residential or branch address is required.', 422);
    if (password.length < 8) failHttp('Password must be at least 8 characters.', 422);
    if (confirmPassword && password !== confirmPassword) failHttp('Passwords do not match.', 422);

    const fyCode = resolveFinancialYearCodeIST();
    const monthCode = getIstMonthCode();
    const seq = await allocateSequence(`USER_${fyCode}_${monthCode}`);
    const issuedUserId = `MC${fyCode}${monthCode}${String(seq).padStart(4, '0')}`;
    const newUid = `USER_${issuedUserId}`;

    try {
      await setDoc(doc(db, 'users', newUid), {
        uid: newUid,
        userId: issuedUserId,
        fullName,
        role,
        status: 'ACTIVE',
        branch,
        designation,
        departmentCode,
        joiningDate,
        isMasterAdmin: false,
        mobileVerified: false,
        emailVerified: Boolean(email),
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
      await setDoc(doc(db, 'users', newUid, 'private', 'info'), {
        uid: newUid,
        email,
        mobile,
        address,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
      await writeSecurityLog(
        'USER_CREATED',
        currentProfile.userId,
        `Provisioned ${role} user ${issuedUserId} (${fullName}) in Firestore.`
      );
      return okEnvelope({
        requiresApproval: false,
        user: {
          id: seq,
          userId: issuedUserId,
          fullName,
          email,
          role,
          mobile,
          address,
          avatarInitials: fullName.split(' ').map((p) => p[0]).slice(0, 2).join('').toUpperCase() || 'MC',
          branch,
          designation,
          departmentCode,
          joiningDate,
          status: 'ACTIVE',
          mobileVerified: false,
          emailVerified: Boolean(email),
          permissions: buildPermissionsForRole(role),
        },
      }) as ApiResponseEnvelope<T>;
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `users/${newUid}`);
    }
  }

  const extendedHandled = await handleExtendedFirebaseEndpoint<T>({
    pathname,
    searchParams,
    method,
    body,
    uid,
    currentProfile,
    isBootAdmin,
    listShared: async (col) =>
      (await getDocs(collection(db, col))).docs.map((d) => d.data() as Record<string, unknown>),
    listScoped: listCollectionScoped,
    allocateSequence,
    writeSecurityLog,
    normalizeCustomer: normalizeCustomerDoc,
    normalizeService: normalizeServiceDoc,
    normalizeApplication: normalizeApplicationDoc,
    normalizePayment: normalizePaymentDoc,
    normalizeExpense: normalizeExpenseDoc,
    normalizeRefund: normalizeRefundDoc,
  });
  if (extendedHandled) return extendedHandled;

  failHttp(
    `Endpoint ${method} ${pathname} is not available in direct Firebase mode. Connect the Express backend server for this operation.`,
    501
  );
}
