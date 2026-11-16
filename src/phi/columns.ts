import type { PhiColumn, PhiKind } from "../types.ts";

/**
 * Which columns hold protected health information, by name. A name match is a guess, so the report
 * prints the map for the owner to correct; nothing here reads row values.
 */

/** Clinical content: on any table, these names mean health data. */
const HEALTH = [
  /^(diagnos[ie]s|diagnosis_\w+|\w+_diagnosis|icd(10)?(_codes?)?|conditions?|medical_conditions?|\w+_conditions?)$/,
  /^(medications?|\w+_medications?|medicines?|prescriptions?|drugs?|dosages?|rx\w*)$/,
  /^(allerg(y|ies)|symptoms?|\w+_symptoms?|treatments?|treatment_\w+|procedures?|vitals?|blood_(type|pressure|group)|bmi|heart_rate)$/,
  /^(lab_\w+|test_results?|results?_(pdf|file|url)|imaging\w*|radiology\w*|pathology\w*)$/,
  /^(medical_\w+|health_\w+|clinical_\w+|chart_notes?|soap_notes?|progress_notes?|visit_notes?|doctor_notes?|therapy_\w+)$/,
  /^(chief_complaint|complaint|mental_health\w*|pregnan\w+|disabilit(y|ies)|hiv\w*|genetic\w*|immuni[sz]ations?|vaccin\w+)$/,
];

/** Ties a record to a person in a health context: PHI identifiers from the HIPAA Safe Harbor list. */
const IDENTIFIER = [
  /^(dob|date_of_birth|birth_?date|birthday)$/,
  /^(ssn|social_security\w*|national_id\w*|sin|tckn|tc_?kimlik\w*|aadhaa?r\w*|cpf|nric|pesel|nino|passport\w*)$/,
  /^(mrn|medical_record_\w+|patient_number|chart_number)$/,
  /^(insurance\w*|\w+_insurance\w*|member_id|policy_number|group_number|medicaid\w*|medicare\w*|health_plan\w*)$/,
];

/** Free-text columns that are clinical only on a clinical table (a "notes" column on invoices is not PHI). */
const CLINICAL_CONTEXT = [/^(notes?|reason|reason_for_visit|description|summary|comments?|history|findings?)$/];

/** Tables whose rows are about a patient's care. */
const CLINICAL_TABLE =
  /(^|_)(patients?|appointments?|visits?|encounters?|consultations?|intake\w*|medical\w*|health\w*|prescriptions?|labs?|lab_\w+|charts?|treatments?|diagnos\w+|clinical\w*|therapy\w*|sessions?_notes?|referrals?|immuni\w+)($|_)/;

/** Plain identifiers that are PHI on a clinical table (name, phone) but too common to search code for. */
const PERSON = /^(full_name|first_name|last_name|name|email|phone|phone_number|address|zip|postal_code)$/;

/** Tables whose name alone says every row is a health record, whatever the columns are called. */
const RECORD_TABLE =
  /(^|_)(medical_records?|health_records?|patient_records?|clinical_records?|lab_results?|lab_reports?|prescriptions?|diagnos[ie]s|medications?|vaccinations?|immuni[sz]ations?|allerg(y|ies))$/;

/** A column that ties a row to a person. */
const PERSON_LINK = /^(user|patient|member|family_member|profile|person|owner|client|account)_?id$/;

/** Bookkeeping columns: keys and timestamps carry no health data even on a health-record table. */
const BOOKKEEPING = /^(id|uuid|\w+_id|created_at|updated_at|deleted_at|inserted_at)$/;

export const isClinicalTable = (table: string): boolean => CLINICAL_TABLE.test(table.replace(/^public\./, ""));

/** The PHI kind of one column of `table`, or undefined when its name does not say it holds PHI. */
export function phiKind(table: string, column: string): PhiKind | undefined {
  const name = column.toLowerCase();
  if (HEALTH.some((re) => re.test(name))) return "health";
  if (IDENTIFIER.some((re) => re.test(name))) return "identifier";
  if (isClinicalTable(table) && CLINICAL_CONTEXT.some((re) => re.test(name))) return "health";
  return undefined;
}

/**
 * PHI columns of a table. A table holds PHI when it has a health column, or is a clinical table with an
 * identifier; on such a table the plain person fields (name, phone) are PHI too, and are listed last.
 */
export function phiColumns(table: string, columns: string[]): PhiColumn[] {
  const found = columns.flatMap((name): PhiColumn[] => {
    const kind = phiKind(table, name);
    return kind ? [{ name, kind }] : [];
  });
  const aboutPerson = columns.some((c) => PERSON_LINK.test(c.toLowerCase()));
  if (aboutPerson && RECORD_TABLE.test(table.replace(/^public\./, "").toLowerCase())) {
    // medical_records(user_id, file_url, extracted_data…): the name says what the rows are. A list of
    // drugs with no link to a person (a medications catalogue) is not a record.
    for (const name of columns) {
      if (
        !found.some((c) => c.name === name) &&
        !BOOKKEEPING.test(name.toLowerCase()) &&
        !PERSON.test(name.toLowerCase())
      ) {
        found.push({ name, kind: "health" });
      }
    }
  }
  const health = found.some((c) => c.kind === "health");
  const identifier = found.some((c) => c.kind === "identifier");
  if (!health && !(identifier && isClinicalTable(table))) {
    // An identifier alone (a dob on a user profile) is personal data, not health data.
    return [];
  }
  const person = columns
    .filter((c) => PERSON.test(c.toLowerCase()))
    .map((name) => ({ name, kind: "identifier" as const }));
  return [...found, ...person];
}

/** Columns worth searching code for: everything but the plain person fields, which every app has. */
export const searchable = (columns: PhiColumn[]): string[] =>
  columns.filter((c) => !PERSON.test(c.name.toLowerCase())).map((c) => c.name);
