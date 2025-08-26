const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager");
const tm = new TaskManager("./TODO.json");

async function claimTask() {
  const data = await tm.readTodo();
  const taskId = "task_1756169692630_4d65llbhg";
  const agentId = "development_session_1756169239776_1_general_317c4734";
  
  const task = data.tasks.find(t => t.id === taskId);
  if (!task) {
    console.log("Task not found");
    return;
  }
  
  if (task.assigned_agent || task.claimed_by) {
    console.log("❌ Task already claimed by:", task.assigned_agent || task.claimed_by);
    return;
  }
  
  console.log("✅ Task available, claiming:", task.title);
  const result = await tm.claimTask(taskId, agentId, "normal");
  console.log("✅ Task claimed successfully:", JSON.stringify(result, null, 2));
}

claimTask();