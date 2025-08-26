import { createRequire } from "module";
const require = createRequire(import.meta.url);

const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager");
const tm = new TaskManager("./TODO.json");

tm.claimTask("task_1756168669294_ejk1jjypf", "claude_code_agent", "high")
  .then((result) => {
    console.log("✅ Critical bug task claimed:", result.success);
    if (result.success) {
      console.log("Task:", result.task.title);
    }
  })
  .catch((error) => {
    console.log("❌ Failed to claim task:", error.message);
  });
