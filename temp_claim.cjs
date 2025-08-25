const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager");
const tm = new TaskManager("./TODO.json");
tm.claimTask("task_1756139817983_m7jnkhe9e", "development_session_1756161077548_1_general_842bef59", "normal").then(result => {
  console.log("Claim result:", JSON.stringify(result, null, 2));
}).catch(error => {
  console.error("Claim error:", error.message);
});
