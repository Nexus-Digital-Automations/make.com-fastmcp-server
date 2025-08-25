const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager");
const tm = new TaskManager("./TODO.json");

tm.updateTaskStatus("task_1756163798804_i0hnybiyg", "completed", "Successfully fixed all 78 explicit any TypeScript warnings by adding proper interfaces and type definitions").then(() => {
  console.log("✅ Warning fix task marked as completed");
}).catch(error => {
  console.error("❌ Task completion failed:", error.message);
});