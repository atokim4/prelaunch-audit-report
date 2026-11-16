// Stand-in for the app's database: records which users were upgraded.
const upgraded = [];

async function markPaid(userId) {
  upgraded.push(userId);
}

module.exports = { upgraded, markPaid };
