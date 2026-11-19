import {
  collection,
  onSnapshot,
  query,
  Unsubscribe,
} from 'firebase/firestore';
import {
  ErpServiceItem,
  ServiceCategoryItem,
  ServiceSubcategoryItem,
} from '../modules/types';
import {
  OperationType,
  auth,
  db,
  handleFirestoreError,
  isFirebaseConfigured,
  timestampToIso,
} from './firebase';

export function normalizeCategoryDoc(
  raw: Record<string, unknown>,
  fallbackIndex = 0
): ServiceCategoryItem {
  const id = Number(raw.id || fallbackIndex + 1);
  return {
    id,
    code: String(raw.code || ''),
    name: String(raw.name || ''),
    description: String(raw.description || ''),
    displayOrder:
      raw.displayOrder !== undefined && raw.displayOrder !== null
        ? Number(raw.displayOrder)
        : id,
    status: (raw.status as ServiceCategoryItem['status']) || 'active',
    proposedBy: String(raw.proposedBy || ''),
    approvedBy: raw.approvedBy ? String(raw.approvedBy) : null,
    createdBy: raw.createdBy ? String(raw.createdBy) : undefined,
    updatedBy: raw.updatedBy ? String(raw.updatedBy) : undefined,
    createdAt: raw.createdAt ? timestampToIso(raw.createdAt) : undefined,
    updatedAt: raw.updatedAt ? timestampToIso(raw.updatedAt) : undefined,
  };
}

export function normalizeSubcategoryDoc(
  raw: Record<string, unknown>,
  fallbackIndex = 0
): ServiceSubcategoryItem {
  const id = Number(raw.id || fallbackIndex + 1);
  return {
    id,
    code: String(raw.code || ''),
    categoryId: Number(raw.categoryId || 1),
    categoryName: String(raw.categoryName || ''),
    name: String(raw.name || ''),
    description: String(raw.description || ''),
    displayOrder:
      raw.displayOrder !== undefined && raw.displayOrder !== null
        ? Number(raw.displayOrder)
        : id,
    status: (raw.status as ServiceSubcategoryItem['status']) || 'active',
    createdBy: raw.createdBy ? String(raw.createdBy) : undefined,
    updatedBy: raw.updatedBy ? String(raw.updatedBy) : undefined,
    createdAt: raw.createdAt ? timestampToIso(raw.createdAt) : undefined,
    updatedAt: raw.updatedAt ? timestampToIso(raw.updatedAt) : undefined,
  };
}

export function normalizeServiceDoc(raw: Record<string, unknown>): ErpServiceItem {
  const serviceCharge = Number(raw.serviceCharge ?? raw.customerCharge ?? 0);
  const serviceCost = Number(raw.serviceCost ?? 0);
  const govtFee = Number(raw.govtFee ?? 0);
  const additionalCharges = Number(raw.additionalCharges ?? 0);
  const totalCustomerCharge =
    raw.totalCustomerCharge !== undefined && raw.totalCustomerCharge !== null
      ? Number(raw.totalCustomerCharge)
      : raw.customerCharge !== undefined && raw.customerCharge !== null
      ? Number(raw.customerCharge)
      : Math.round((serviceCharge + govtFee + additionalCharges) * 100) / 100;
  const profitAmount =
    raw.profitAmount !== undefined && raw.profitAmount !== null
      ? Number(raw.profitAmount)
      : Math.round((serviceCharge + additionalCharges - serviceCost) * 100) / 100;

  return {
    id: Number(raw.id || 1),
    serviceId: String(raw.serviceId || ''),
    serviceCode: String(raw.serviceCode || ''),
    name: String(raw.name || ''),
    categoryId: Number(raw.categoryId || 1),
    categoryName: String(raw.categoryName || 'General'),
    subcategoryId:
      raw.subcategoryId !== undefined && raw.subcategoryId !== null
        ? Number(raw.subcategoryId)
        : undefined,
    subcategoryName: raw.subcategoryName ? String(raw.subcategoryName) : undefined,
    description: String(raw.description || ''),
    serviceCharge,
    serviceCost,
    govtFee,
    additionalCharges,
    totalCustomerCharge,
    customerCharge: totalCustomerCharge,
    profitAmount,
    status: (raw.status as ErpServiceItem['status']) || 'Active',
    availability: (raw.availability as ErpServiceItem['availability']) || 'Available',
    serviceInstructions: String(raw.serviceInstructions || raw.termsAndConditions || ''),
    termsAndConditions: String(raw.termsAndConditions || raw.serviceInstructions || ''),
    displayOrder:
      raw.displayOrder !== undefined && raw.displayOrder !== null
        ? Number(raw.displayOrder)
        : Number(raw.id || 1),
    sla: (raw.sla as ErpServiceItem['sla']) || {
      processingMode: 'FIXED',
      expectedDays: 3,
      minDays: 1,
      maxDays: 5,
      dayType: 'WORKING',
      excludeHolidays: true,
      startEvent: 'ON_SUBMIT',
      pauseOnStatuses: ['Pending Customer'],
      warningThresholdPct: 75,
      breachThresholdHours: 24,
    },
    requiredDocuments: Array.isArray(raw.requiredDocuments)
      ? (raw.requiredDocuments as ErpServiceItem['requiredDocuments'])
      : [],
    currentFormVersion: Number(raw.currentFormVersion || 1),
    formVersions: Array.isArray(raw.formVersions)
      ? (raw.formVersions as ErpServiceItem['formVersions'])
      : [],
    automationRules: Array.isArray(raw.automationRules)
      ? (raw.automationRules as ErpServiceItem['automationRules'])
      : [],
    deletedAt: raw.deletedAt ? String(raw.deletedAt) : null,
    createdBy: raw.createdBy ? String(raw.createdBy) : undefined,
    updatedBy: raw.updatedBy ? String(raw.updatedBy) : undefined,
    createdAt: raw.createdAt ? timestampToIso(raw.createdAt) : undefined,
    updatedAt: raw.updatedAt ? timestampToIso(raw.updatedAt) : undefined,
  };
}

export interface ServicesRealtimeCallbacks {
  onCategories: (items: ServiceCategoryItem[]) => void;
  onSubcategories: (items: ServiceSubcategoryItem[]) => void;
  onServices: (items: ErpServiceItem[]) => void;
  onError?: (err: unknown) => void;
}

export function subscribeServicesModuleRealtime(
  callbacks: ServicesRealtimeCallbacks
): Unsubscribe {
  if (!isFirebaseConfigured() || !db || !auth?.currentUser) {
    return () => {};
  }

  const unsubCats = onSnapshot(
    query(collection(db, 'serviceCategories')),
    (snap) => {
      const items = snap.docs
        .map((d, idx) => normalizeCategoryDoc(d.data() as Record<string, unknown>, idx))
        .sort((a, b) => (a.displayOrder ?? a.id) - (b.displayOrder ?? b.id));
      callbacks.onCategories(items);
    },
    (error) => {
      try {
        handleFirestoreError(error, OperationType.LIST, 'serviceCategories');
      } catch (wrapped) {
        callbacks.onError?.(wrapped);
      }
    }
  );

  const unsubSubs = onSnapshot(
    query(collection(db, 'serviceSubcategories')),
    (snap) => {
      const items = snap.docs
        .map((d, idx) => normalizeSubcategoryDoc(d.data() as Record<string, unknown>, idx))
        .sort(
          (a, b) =>
            a.categoryId - b.categoryId ||
            (a.displayOrder ?? a.id) - (b.displayOrder ?? b.id) ||
            a.id - b.id
        );
      callbacks.onSubcategories(items);
    },
    (error) => {
      try {
        handleFirestoreError(error, OperationType.LIST, 'serviceSubcategories');
      } catch (wrapped) {
        callbacks.onError?.(wrapped);
      }
    }
  );

  const unsubServices = onSnapshot(
    query(collection(db, 'services')),
    (snap) => {
      const items = snap.docs
        .map((d) => normalizeServiceDoc(d.data() as Record<string, unknown>))
        .filter((s) => !s.deletedAt)
        .sort((a, b) => (a.displayOrder ?? a.id) - (b.displayOrder ?? b.id) || a.id - b.id);
      callbacks.onServices(items);
    },
    (error) => {
      try {
        handleFirestoreError(error, OperationType.LIST, 'services');
      } catch (wrapped) {
        callbacks.onError?.(wrapped);
      }
    }
  );

  return () => {
    unsubCats();
    unsubSubs();
    unsubServices();
  };
}
