const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager");

async function checkInProgressTasks() {
  const tm = new TaskManager("./TODO.json");
  const data = await tm.readTodo();
  
  const inProgress = data.tasks.filter(t => t.status === "in_progress");
  
  console.log("Tasks in progress:");
  inProgress.forEach(t => {
    console.log(`\nTask: ${t.title}`);
    console.log(`ID: ${t.id}`);
    console.log(`Category: ${t.category}`);
    console.log(`Priority: ${t.priority}`);
    console.log(`Assigned to: ${t.assigned_agent || t.claimed_by || "none"}`);
    console.log(`Description: ${t.description}`);
  });
}

checkInProgressTasks().catch(console.error);