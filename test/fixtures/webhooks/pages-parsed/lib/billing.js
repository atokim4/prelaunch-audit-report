// Stand-in for the app's database: records which users were upgraded.
export const upgraded = [];

export async function markPaid(userId) {
  upgraded.push(userId);
}
