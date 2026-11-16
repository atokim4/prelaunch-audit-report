// Stand-in for the app's database: records which users were upgraded.
export const upgraded: string[] = [];

export async function markPaid(userId: string): Promise<void> {
  upgraded.push(userId);
}
