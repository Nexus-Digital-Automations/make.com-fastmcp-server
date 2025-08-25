const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager");
const tm = new TaskManager("./TODO.json");

tm.claimTask("task_1756163798804_i0hnybiyg", "development_session_1756162643591_1_general_ea4be754", "normal").then(result => {
  console.log("✅ Claimed warning fix task:", result.task.id);
}).catch(error => {
  console.error("❌ Claim failed:", error.message);
});